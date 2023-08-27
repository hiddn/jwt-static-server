package unet_auth

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
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hiddn/unet_auth/confighandler"
)

var Config confighandler.Configuration
var JwtInfos jwtInfos
var Access AccessData

type jwtInfos struct {
	Jwks          *keyfunc.JWKS
	JwksURL       string
	ApiRefreshURL string
}

func Init() {
	var err error

	var configFile = "config.json"
	Config = confighandler.ReadConf(configFile)
	getJSONfromFile(configFile, &Config)

	fmt.Println("what: ", Config.Groups_file)
	//Access.LoadUsersAndPages("pages.json", "groups.json", "users.json")
	Access.LoadUsersAndPages(Config.Pages_file, Config.Groups_file, Config.Users_file)

	jwksURL := Config.Csc_api_url + Config.Csc_api_jwks_path
	JwtInfos.Jwks, err = InitJWKS(jwksURL)
	if err != nil {
		log.Fatalf("Could not obtain JWKS from %s", jwksURL)
	}

	//vue page - if served locally
	if Config.Login_content_serve_local {
		fs := http.FileServer(http.Dir(Config.Login_content_dir))
		http.Handle(Config.Login_url, http.StripPrefix(Config.Login_url, fs))
	}

	http.HandleFunc(Config.Static_content_urlpath, serveStatic)
	http.HandleFunc("/logout", handleLogout)
	//http.HandleFunc("/setcookie", handleSetJwtCookie)

	log.Print("Listening on :3000...")
	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal(err)
	}
	JwtInfos.Jwks.EndBackground()
}

func serveStatic(w http.ResponseWriter, r *http.Request) {
	var loginErrStr string = ""
	dir := Config.Static_content_dir
	fs := http.FileServer(http.Dir(dir))
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
			realHandler := http.StripPrefix(Config.Static_content_urlpath, fs).ServeHTTP
			can_access_page := Access.validateUserAccess(r.URL.Path, userID, username)
			if can_access_page {
				realHandler(w, r)
				return
			} else {
				message := "Unauthorized: Access denied"
				http.Error(w, message, http.StatusUnauthorized)
				return
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
	GroupName string   `json:"group_name"`
	Users     []string `json:"users"`
}

type PageAccess struct {
	// Accepted values: group_name|authed|unrestricted
	Page   string   `json:"page"` // use default if nothing else is found
	Groups []string `json:"groups"`
}

type User struct {
	Username string `json:"username"`
	UserID   int    `json:"user_id"`
}

type AccessData struct {
	PageGroups map[string][]string
	GroupUsers map[string][]string
	UserID     map[string]int

	UserPages     map[string]map[string]int
	userGroups    map[string]int
	DefaultPolicy string
}

func (a *AccessData) LoadUsersAndPages(pages_file, groups_file, users_file string) {
	//getJSONfromFile(users_file, &a.Users)
	getJSONfromFile(pages_file, &a.PageGroups)
	getJSONfromFile(groups_file, &a.GroupUsers)
	a.DefaultPolicy = a.getDefaultPolicy()
	fmt.Println("Default policy:", a.DefaultPolicy)
	a.buildAccessMapByUser()
	//defPerm := a.PageGroups["default"]
}

func (a *AccessData) buildAccessMapByUser() {
	a.UserPages = make(map[string]map[string]int)
	for p, groups := range a.PageGroups {
		for _, g := range groups {
			groupusers, _ := a.GroupUsers[g]
			for _, u := range groupusers {
				if _, ok := a.UserPages[u]; !ok {
					var t map[string]int
					t = make(map[string]int)
					t[p] = a.GetIDbyUsername(u)
					a.UserPages[u] = t
				} else {
					a.UserPages[u][p] = a.GetIDbyUsername(u)
					fmt.Printf("access: u:%s p:%s g:%s\n", u, p, g)
				}
			}
		}
	}
	switch a.DefaultPolicy {
	case "open":
		return
	case "authed":
		return
	case "deny":
		return
	default:
		a.userGroups = make(map[string]int)
		for _, u := range a.GroupUsers[a.DefaultPolicy] {
			usergroup := fmt.Sprintf("%s.%s", a.DefaultPolicy, u)
			a.userGroups[usergroup] = a.GetIDbyUsername(u)
		}
	}
}

func (a *AccessData) IsUserMemberOfGroup(username, group string) bool {
	usergroup := fmt.Sprintf("%s.%s", group, username)
	if _, ok := a.userGroups[usergroup]; ok {
		return true
	}
	return false
}
func (a *AccessData) GetIDbyUsername(username string) int {
	id, ok := a.UserID[username]
	if !ok {
		// UserID not found
		return -1
	}
	return id
}

func (a *AccessData) validateUserAccess(page string, user_id int, username string) (ret bool) {
	ret = false
	printRet := func(ret *bool) {
		fmt.Printf(" Granted: %v\n", *ret)
	}
	defer printRet(&ret)
	fmt.Printf("Validating access. u:%s p:%s...", username, page)
	if _, dontUseDefault := a.PageGroups[page]; !dontUseDefault {
		//fmt.Printf("dontUseDefault=%v, a.DefaultPolicy=%s\na.IsUserMemberOfGroup(username, a.DefaultPolicy)=%v", dontUseDefault, a.DefaultPolicy, a.IsUserMemberOfGroup(username, a.DefaultPolicy))
		switch a.DefaultPolicy {
		case "open":
		case "authed":
			ret = true
			return
		case "deny":
			ret = false
			return
		default:
			ret = a.IsUserMemberOfGroup(username, a.DefaultPolicy)
			return
		}
	}
	//fmt.Printf("Validation for page/user access: u:%s p:%s\n", page, username)
	pages, ok := a.UserPages[username]
	if !ok {
		ret = false
		return
	}
	expectedUserID, ok := pages[page]
	if !ok {
		ret = false
		return
	}
	if expectedUserID == user_id || expectedUserID == -1 {
		ret = true
		return
	}
	ret = false
	return
}

func (a *AccessData) getDefaultPolicy() string {
	defaultGroups, ok := a.PageGroups["default"]
	if !ok {
		log.Printf("Default permission missing.")
		return "deny"
	}
	if len(defaultGroups) > 0 {
		group := defaultGroups[0]
		if _, ok := a.GroupUsers[group]; !ok {
			if group != "deny" && group != "authed" && group != "open" {
				return "deny"
			}
			log.Fatalf("AccessData: default page specifies group that does not exist. Accepted values: authed, deny, open, or <groupname>\n")
			return group
		}
		return group
	}
	return "deny"
}

func getJSONfromFile(file string, ptr interface{}) {
	content, err := os.ReadFile(file)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}
	if err := json.Unmarshal(content, &ptr); err != nil {
		log.Fatalf("getJSONfromFile() error with %s: %s", file, err)
	}
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
	//fmt.Println("jwt token:", jwtToken)
	token, err := jwt.Parse(jwtToken, JwtInfos.Jwks.Keyfunc)
	if err != nil {
		log.Printf("Failed to parse the JWT.\nError: %s\n", err.Error())
		return false, nil
	}

	// Check if the token is valid.
	if !token.Valid {
		return false, nil
	}
	//fmt.Println("Claims: ", token.Claims)
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
		return isValid, claims
	}
	isValid, claims = validateToken(jwtTokens.RefreshToken)
	if isValid {
		// Refresh token still valid.
		// We need to get a new access token with the refresh token.
		jwtRefreshURL := Config.Csc_api_url + Config.Csc_api_refresh_path
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
	fmt.Println("refreshToken() called.")
	var newJwtTokens JwtTokens
	var rtReq refreshTokenRequest
	rtReq.RefreshToken = refreshToken
	//var data = []byte(fmt.Sprintf(`{"refresh_token": "%s"}`, refreshToken))
	data, err := json.Marshal(rtReq)
	if err != nil {
		log.Fatalf("refreshToken(): abnormal error. This shouldn't have happened")
		//return newJwtTokens, errors.New("refreshToken(): abnormal error. This shouldn't have happened")
	}
	//fmt.Println(string(data))
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
	//fmt.Println("debug: ", string(tokenAsJSON))
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
	//fmt.Println("token: ", string(jsonJwtByteArr))
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
	var loginErrStr string
	if err == nil {
		c.Expires = time.Unix(1414414788, 1414414788000)
		http.SetCookie(w, c)
		loginErrStr = "You are now logged out"
	} else {
		loginErrStr = "You were already logged out"
	}
	loginErrStr = fmt.Sprintf("&message=%s", url.QueryEscape(loginErrStr))
	login_path := fmt.Sprintf("/login?next=%s%s", "/", loginErrStr)
	http.Redirect(w, r, login_path, http.StatusSeeOther)
}

type JwtTokens struct {
	AccessToken  string `json:"access_token" extensions:"x-order=0"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" valid:"required"`
}
