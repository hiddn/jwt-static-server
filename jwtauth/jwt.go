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

type JwtInfos struct {
	Jwks          *keyfunc.JWKS
	JwksURL       string
	ApiRefreshURL string
}

type JwtTokens struct {
	AccessToken  string `json:"access_token" extensions:"x-order=0"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" valid:"required"`
}

func InitJWKS(jwksURL string, ApiRefreshURL string) (JwtInfos, error) {
	var Jwt JwtInfos
	var err error

	// Create a context that, when cancelled, ends the JWKS background refresh goroutine.
	ctx, _ := context.WithCancel(context.Background())

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
func (Jwt JwtInfos) ValidateJWTTokens(w http.ResponseWriter, jwtTokens JwtTokens, jwtRefreshURL string) (isValid bool, claims jwt.MapClaims) {
	//var isValid bool
	//var claims jwt.MapClaims
	isValid, claims = Jwt.validateToken(jwtTokens.AccessToken)
	if isValid {
		return isValid, claims
	}
	isValid, claims = Jwt.validateToken(jwtTokens.RefreshToken)
	if isValid {
		// Refresh token still valid.
		// We need to get a new access token with the refresh token.
		//jwtRefreshURL := Config.Csc_api_url + Config.Csc_api_refresh_path
		newJwtTokens, err := refreshToken(w, jwtRefreshURL, jwtTokens.RefreshToken)
		if err != nil {
			isValid = false
			return isValid, claims
		}
		isValid, claims = Jwt.validateToken(newJwtTokens.AccessToken)
	}
	return isValid, claims
}

func refreshToken(w http.ResponseWriter, url string, refreshToken string) (JwtTokens, error) {
	debug.LN("refreshToken() called.")
	var newJwtTokens JwtTokens
	var rtReq refreshTokenRequest
	rtReq.RefreshToken = refreshToken
	//var data = []byte(fmt.Sprintf(`{"refresh_token": "%s"}`, refreshToken))
	data, err := json.Marshal(rtReq)
	if err != nil {
		log.Fatalf("refreshToken(): abnormal error. This shouldn't have happened")
		//return newJwtTokens, errors.New("refreshToken(): abnormal error. This shouldn't have happened")
	}
	//debug.LN(string(data))
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
	var res map[string]interface{}
	json.NewDecoder(response.Body).Decode(&res)
	//debug.LN("res =", res)
	at, _ := res["access_token"]
	newJwtTokens.AccessToken = at.(string)
	rt, _ := res["refresh_token"]
	newJwtTokens.RefreshToken = rt.(string)
	tokenAsJSON, _ := json.Marshal(newJwtTokens)
	//debug.LN("debug: ", string(tokenAsJSON))
	tokenAsJSONb64 := base64.StdEncoding.EncodeToString(tokenAsJSON)
	setCookie(w, "jwt_token", tokenAsJSONb64)
	return newJwtTokens, err
}

func GetJwtTokensFromCookie(r *http.Request) (JwtTokens, error) {
	var jwtTokens JwtTokens
	jsonJwt, err := r.Cookie("jwt_token")
	if err != nil {
		return jwtTokens, err
	}
	jsonJwtByteArr, err := base64.StdEncoding.DecodeString(jsonJwt.Value)
	if err != nil {
		fmt.Println("fatal error decoding jwt base64: ", err)
		return jwtTokens, err
	}
	err = json.Unmarshal(jsonJwtByteArr, &jwtTokens)
	if err != nil {
		fmt.Println("error loading json: ", err)
		return jwtTokens, err
	}
	//debug.LN("token: ", string(jsonJwtByteArr))
	return jwtTokens, err
}

/*
func handleSetJwtCookie(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t test_struct
	err := decoder.Decode(&t)
	if err != nil {
		panic(err)
	}
	log.Printf("json decoder: %s\n", t.Test)

	r.ParseForm()
	log.Println("r.PostForm", r.PostForm)
	log.Println("r.Form", r.Form)
	cookieName := "jwt_token"
	cookieValue := r.PostFormValue(cookieName)
	cookieValue = r.Form.Get(cookieName)
	setCookie(w, cookieName, cookieValue)
	debug.LN(r.Body)
	Debugf("Setcookie: jwt_token = %s\n", cookieValue)
}
*/

func setCookie(w http.ResponseWriter, cookieName, cookieValue string) {
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, cookie)
}

func getTokenInfosFromB64(jwtToken string) {

}
