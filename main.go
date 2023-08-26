package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

var Config Configuration

var prefix = "/"
var jwksURL = "http://127.0.0.1/.well-known/jwks.json"
var jwtRefreshURL = "http://127.0.0.1:6000/api/v1/authn/refresh"
var jwks *keyfunc.JWKS

type jwtInfos struct {
	Jwks          *keyfunc.JWKS
	JwksURL       string
	ApiRefreshURL string
}

func main() {
	var err error

	var configFile = "config.json"
	Config = ReadConf(configFile)
	//jwtRefreshURL = Config.csc_api_url + Config.csc_api_url // Marche pas en ce moment

	jwks, err = InitJWKS(jwksURL)
	if err != nil {
		log.Fatalf("Could not obtain JWKS from %s", jwksURL)
	}

	//vue page
	fs := http.FileServer(http.Dir("./dist"))
	http.Handle("/login/", http.StripPrefix("/login/", fs))

	http.HandleFunc(prefix, serveStatic)
	http.HandleFunc("/logout", handleLogout)
	//http.HandleFunc("/setcookie", handleSetJwtCookie)

	log.Print("Listening on :3000...")
	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal(err)
	}
	jwks.EndBackground()
}

func serveStatic(w http.ResponseWriter, r *http.Request) {
	var loginErrStr string = ""
	dir := "./site"
	fs := http.FileServer(http.Dir(dir))
	/* Add login checks here */
	jwtTokens, err := getJwtTokensFromCookie(r)
	if err != nil {
		fmt.Println("error with getJwtTokenFromCookie(): ", err)
	} else {
		//fmt.Println("access token: ", jwtTokens.AccessToken)
		var isValid bool
		var claims jwt.MapClaims
		isValid, claims = validateJWTTokens(w, jwtTokens)
		//isValid, claims = validateToken(jwtTokens.AccessToken)
		if isValid {
			var username string
			var userIDf float64
			var userID int
			var ok bool
			username, ok = claims["username"].(string)
			if !ok {
				log.Fatalln("Misconstructed jwt token. Missing username in claims:", claims)
			}
			userIDf, ok = claims["user_id"].(float64)
			if !ok {
				log.Fatalln("Misconstructed jwt token. Missing user_id in claims:", claims)
			}
			userID = int(userIDf)
			realHandler := http.StripPrefix(prefix, fs).ServeHTTP
			can_access_page := validateUserAccess(r.URL.Path, userID, username)
			if can_access_page {
				realHandler(w, r)
				return
			} else {
				loginErrStr = "Access denied"
			}
		}
	}
	if loginErrStr != "" {
		loginErrStr = fmt.Sprintf("&message=%s", url.QueryEscape(loginErrStr))
	}
	login_path := fmt.Sprintf("/login?next=%s%s", r.URL.Path, loginErrStr)
	http.Redirect(w, r, login_path, http.StatusSeeOther)
	return
}

type Group struct {
	// GroupName contains a list of users
	GroupName []string `json:"group_name"`
}

type PageAccess struct {
	// Accepted values: group_name|authed|unrestricted
	Page   string  `json:"page"` // use default if nothing else is found
	Groups []Group `json:"groups"`
}

type User struct {
	Username string `json:"username"`
	UserID   int    `json:"user_id"`
}

func validateUserAccess(page string, user_id int, username string) bool {
	if username == "Admin" {
		return true
	}
	return false
}

func InitJWKS(jwksURL string) (*keyfunc.JWKS, error) {
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
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}
	return jwks, err
}

// Function to validate a base64 JWT Access token or Refresh token
func validateToken(jwtToken string) (bool, jwt.MapClaims) {
	// Parse the JWT.
	fmt.Println("jwt token:", jwtToken)
	token, err := jwt.Parse(jwtToken, jwks.Keyfunc)
	if err != nil {
		log.Printf("Failed to parse the JWT.\nError: %s\n", err.Error())
		return false, nil
	}

	// Check if the token is valid.
	if !token.Valid {
		return false, nil
	}
	fmt.Println("Claims: ", token.Claims)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, nil
	}
	//fmt.Println("username =", claims["username"])
	return true, claims
}
func validateJWTTokens(w http.ResponseWriter, jwtTokens JwtTokens) (isValid bool, claims jwt.MapClaims) {
	//var isValid bool
	//var claims jwt.MapClaims
	isValid, claims = validateToken(jwtTokens.AccessToken)
	if isValid {
		//return isValid, claims
	}
	isValid, claims = validateToken(jwtTokens.RefreshToken)
	if isValid {
		// Refresh token still valid.
		// We need to get a new access token with the refresh token.
		newJwtTokens, err := refreshToken(w, jwtRefreshURL, jwtTokens.RefreshToken)
		if err != nil {
			isValid = false
			return isValid, claims
		}
		isValid, claims = validateToken(newJwtTokens.AccessToken)
	}
	return isValid, claims
}

func refreshToken(w http.ResponseWriter, url string, refreshToken string) (JwtTokens, error) {
	fmt.Println("refreshToken() called. url =", url)
	var newJwtTokens JwtTokens
	var rtReq refreshTokenRequest
	rtReq.RefreshToken = refreshToken
	//var data = []byte(fmt.Sprintf(`{"refresh_token": "%s"}`, refreshToken))
	data, err := json.Marshal(rtReq)
	if err != nil {
		log.Fatalf("refreshToken(): abnormal error. This shouldn't have happened")
		//return newJwtTokens, errors.New("refreshToken(): abnormal error. This shouldn't have happened")
	}
	fmt.Println(string(data))
	response, err := http.Post(url, "application/json", bytes.NewBuffer([]byte(data)))
	if err != nil {
		fmt.Println("error in refreshToken: ", err)
		return newJwtTokens, err
	}
	defer response.Body.Close()

	fmt.Println("response.status =", response.Status)
	if response.StatusCode != 200 {
		return newJwtTokens, errors.New("refresh token refused: Unauthorized")
	}
	var res map[string]interface{}
	json.NewDecoder(response.Body).Decode(&res)
	//fmt.Println("res =", res)
	at, _ := res["access_token"]
	newJwtTokens.AccessToken = at.(string)
	rt, _ := res["refresh_token"]
	newJwtTokens.RefreshToken = rt.(string)
	tokenAsJSON, _ := json.Marshal(newJwtTokens)
	fmt.Println("debug: ", string(tokenAsJSON))
	tokenAsJSONb64 := base64.StdEncoding.EncodeToString(tokenAsJSON)
	setCookie(w, "jwt_token", tokenAsJSONb64)
	return newJwtTokens, err
}

func getJwtTokensFromCookie(r *http.Request) (JwtTokens, error) {
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
	fmt.Println("token: ", string(jsonJwtByteArr))
	return jwtTokens, err
}

type test_struct struct {
	Test string
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
	fmt.Println(r.Body)
	fmt.Printf("Setcookie: jwt_token = %s\n", cookieValue)
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

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("jwt_token")
	if err != nil {
		return
	}
	c.Expires = time.Unix(1414414788, 1414414788000)
	http.SetCookie(w, c)
}

/*
func serveTemplate(w http.ResponseWriter, r *http.Request) {
	lp := filepath.Join("templates", "layout.html")
	fp := filepath.Join("templates", filepath.Clean(r.URL.Path))

	tmpl, _ := template.ParseFiles(lp, fp)
	tmpl.ExecuteTemplate(w, "layout", nil)
}
*/

type JwtTokens struct {
	AccessToken  string `json:"access_token" extensions:"x-order=0"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" valid:"required"`
}
