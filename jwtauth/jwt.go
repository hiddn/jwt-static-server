package jwtauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hiddn/jwt-static-server/debug"
)

type RefreshCallBack func(http.ResponseWriter, *http.Request, JwtTokens)

type JwtInfos struct {
	Jwks          *keyfunc.JWKS
	JwksURL       string
	ApiRefreshURL string
	CancelFunc    context.CancelFunc
}

type JwtTokens struct {
	AccessToken  string `json:"access_token" extensions:"x-order=0"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1"`
}

type JwtAccessToken struct {
	AccessToken  string `json:"access_token" extensions:"x-order=0"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1"`
}

type JwtRefreshToken struct {
	RefreshToken string `json:"refresh_token" valid:"required"`
}

func InitJWKS(jwksURL string, ApiRefreshURL string) (JwtInfos, error) {
	var Jwt JwtInfos
	var ctx context.Context
	var err error

	// Create a context that, when cancelled, ends the JWKS background refresh goroutine.
	ctx, Jwt.CancelFunc = context.WithCancel(context.Background())

	// Create the keyfunc options. Use an error handler that logs. Refresh the JWKS when a JWT signed by an unknown KID
	// is found or at the specified interval. Rate limit these refreshes. Timeout the initial JWKS refresh request after
	// 10 seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.
	options := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the JWKS from the resource at the given URL.
	Jwt.Jwks, err = keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}
	return Jwt, err
}

// Function to validate a base64 JWT Access token or Refresh token
func (Jwt JwtInfos) validateToken(jwtToken string) (bool, jwt.MapClaims) {
	// Parse the JWT.
	//debug.LN("jwt token:", jwtToken)
	token, err := jwt.Parse(jwtToken, Jwt.Jwks.Keyfunc)
	if err != nil {
		log.Printf("Failed to parse the JWT.\nError: %s\n", err.Error())
		return false, nil
	}

	// Check if the token is valid.
	if !token.Valid {
		return false, nil
	}
	//debug.LN("Claims: ", token.Claims)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, nil
	}
	//debug.LN("username =", claims["username"])
	return true, claims
}

func (Jwt JwtInfos) ValidateAccessToken(w http.ResponseWriter, r *http.Request, acessToken, jwtRefreshURL, jwtCookieName string, handleRefresh RefreshCallBack) (isValid bool, claims jwt.MapClaims) {
	//func (Jwt JwtInfos) ValidateAccessToken(w http.ResponseWriter, r *http.Request, acessToken, jwtRefreshURL, jwtCookieName string) (isValid bool, claims jwt.MapClaims) {
	//var isValid bool
	//var claims jwt.MapClaims
	isValid, claims = Jwt.validateToken(acessToken)
	if isValid {
		return isValid, claims
	}
	rt_s, err := GetRefreshTokenFromCookie(r, "jwt_token")
	if err != nil {
		debug.LN("GetRefreshTokenFromCookie() failed.")
		isValid = false
		return isValid, claims
	}

	isValid, claims = Jwt.validateToken(rt_s.RefreshToken)
	if isValid {
		// Refresh token still valid.
		// We need to get a new access token with the refresh token.
		//jwtRefreshURL := Config.Csc_api_url + Config.Csc_api_refresh_path
		newJwtTokens, err := refreshToken(w, r, jwtRefreshURL, rt_s.RefreshToken, jwtCookieName)
		if err != nil {
			isValid = false
			return isValid, claims
		}
		isValid, claims = Jwt.validateToken(newJwtTokens.AccessToken)
		handleRefresh(w, r, newJwtTokens)
	}
	return isValid, claims
}

func refreshToken(w http.ResponseWriter, r *http.Request, url, refreshToken, jwtCookieName string) (JwtTokens, error) {
	debug.LN("refreshToken() called.")
	var newJwtTokens JwtTokens
	var rtReq JwtRefreshToken
	rtReq.RefreshToken = refreshToken
	data, err := json.Marshal(rtReq)
	if err != nil {
		log.Fatalf("refreshToken(): abnormal error. This shouldn't have happened")
	}
	response, err := http.Post(url, "application/json", bytes.NewBuffer([]byte(data)))
	if err != nil {
		fmt.Println("error in refreshToken: ", err)
		return newJwtTokens, err
	}
	defer response.Body.Close()

	debug.LN("response.status =", response.Status)
	if response.StatusCode != 200 {
		return newJwtTokens, errors.New("refresh token refused: Unauthorized")
	}
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&newJwtTokens)
	if err != nil {
		return newJwtTokens, fmt.Errorf("refreshToken(): decoding JSON response failed")
	}
	return newJwtTokens, err
}

func GetRefreshTokenFromCookie(r *http.Request, cookieName string) (JwtRefreshToken, error) {
	var jwtRefreshToken JwtRefreshToken
	jsonJwt, err := r.Cookie(cookieName)
	if err != nil {
		return jwtRefreshToken, err
	}
	jsonJwtByteArr, err := base64.StdEncoding.DecodeString(jsonJwt.Value)
	if err != nil {
		fmt.Println("fatal error decoding jwt base64: ", err)
		return jwtRefreshToken, err
	}
	err = json.Unmarshal(jsonJwtByteArr, &jwtRefreshToken)
	if err != nil {
		fmt.Println("error loading json: ", err)
		return jwtRefreshToken, err
	}
	//debug.LN("token: ", string(jsonJwtByteArr))
	return jwtRefreshToken, err
}

func SetJwtCookie(w http.ResponseWriter, cookieName, refreshToken string) {
	data := &JwtRefreshToken{
		RefreshToken: refreshToken,
	}
	tokenAsJSON, _ := json.Marshal(data)
	tokenAsJSONb64 := base64.StdEncoding.EncodeToString(tokenAsJSON)
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    tokenAsJSONb64,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, cookie)

}

func getTokenInfosFromB64(jwtToken string) {

}
