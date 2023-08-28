package unet_auth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hiddn/jwt-static-server/confighandler"
	"github.com/hiddn/jwt-static-server/debug"
	"github.com/hiddn/jwt-static-server/jwtauth"
)

var sites []Site

//var Config confighandler.Configuration

type Site struct {
	Config confighandler.Configuration
	Access AccessData
	Jwt    jwtauth.JwtInfos
}

type AccessData struct {
	S          *Site
	PageGroups map[string][]string
	GroupUsers map[string][]string
	UserID     map[string]int

	UserPages map[string]map[string]int
	// key: 'group.user' value: UserID
	userGroups    map[string]int
	DefaultPolicy string
}

func Init(configFile string) {
	debug.Enable()
	var err error

	var s Site
	s.Access.S = &s
	s.Config = confighandler.ReadConf(configFile)
	getJSONfromFile(configFile, &s.Config)

	//Access.LoadUsersAndPages("pages.json", "groups.json", "users.json")
	s.Access.LoadUsersAndPages(s.Config.Pages_file, s.Config.Groups_file, s.Config.Users_file)

	jwksURL := s.Config.Csc_api_url + s.Config.Csc_api_jwks_path
	jwksRefreshURL := s.Config.Csc_api_url + s.Config.Csc_api_refresh_path
	s.Jwt, err = jwtauth.InitJWKS(jwksURL, jwksRefreshURL)
	if err != nil {
		log.Fatalf("Could not obtain JWKS from %s", jwksURL)
	}

	//vue page - if served locally
	if s.Config.Login_content_serve_local {
		fs := http.FileServer(http.Dir(s.Config.Login_content_dir))
		http.Handle(s.Config.Login_url, http.StripPrefix(s.Config.Login_url, fs))
	}

	http.HandleFunc(s.Config.Static_content_urlpath, s.serveStatic)
	http.HandleFunc("/logout", handleLogout)
	//http.HandleFunc("/setcookie", handleSetJwtCookie)

	log.Print("Listening on :3000...")
	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal(err)
	}
	s.Jwt.Jwks.EndBackground()
}

func (s Site) serveStatic(w http.ResponseWriter, r *http.Request) {
	var fs http.Handler
	servePage := func() {
		realHandler := http.StripPrefix(s.Config.Static_content_urlpath, fs).ServeHTTP
		realHandler(w, r)
	}
	var loginErrStr string = ""
	fs = http.FileServer(http.Dir(s.Config.Static_content_dir))
	jwtTokens, err := jwtauth.GetJwtTokensFromCookie(r)
	if err != nil {
		fmt.Println("error with getJwtTokenFromCookie(): ", err)
	} else {
		//debug.LN("access token: ", jwtTokens.AccessToken)
		var isValid bool
		var claims jwt.MapClaims
		refresURL := fmt.Sprintf("%s%s", s.Config.Csc_api_url, s.Config.Csc_api_refresh_path)
		isValid, claims = s.Jwt.ValidateJWTTokens(w, jwtTokens, refresURL)
		if s.Access.DefaultPolicy == "open" {
			fmt.Printf("(policy: open): serving %s without authentification\n", r.URL.Path)
			servePage()
			return
		}
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
			can_access_page := s.Access.canUserAccessPage(r.URL.Path, userID, username)
			if can_access_page {
				servePage()
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
					debug.F("access: u:%s p:%s g:%s\n", u, p, g)
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
	if expectedUserID, ok := a.userGroups[usergroup]; ok {
		return a.validateUserID(username, expectedUserID)
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

func (a *AccessData) canUserAccessPage(page string, user_id int, username string) (ret bool) {
	ret = false
	printRet := func(ret *bool) {
		if debug.IsEnabled() {
			fmt.Printf(" Granted: %v\n", *ret)
		}
	}
	defer printRet(&ret)
	debug.F("Validating access. u:%s p:%s...", username, page)
	/*
		// that code could eventually be used if I added the possibility
		// to give permissions for all files (and sub-directories) in a directory.
		for {
			parts := strings.Split(page, "/")
			tPage := strings.Join(parts[:len(parts)-1], "/")
			debug.F("Testing %s\n", tPage)
			break
		}
	*/
	if _, dontUseDefault := a.PageGroups[page]; !dontUseDefault {
		// Page is not listed in pages.json
		//debug.F("dontUseDefault=%v, a.DefaultPolicy=%s\na.IsUserMemberOfGroup(username, a.DefaultPolicy)=%v", dontUseDefault, a.DefaultPolicy, a.IsUserMemberOfGroup(username, a.DefaultPolicy))
		switch a.DefaultPolicy {
		case "open":
			ret = true
			return
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
	//debug.F("Validation for page/user access: u:%s p:%s\n", page, username)
	pages, ok := a.UserPages[username]
	if !ok {
		ret = false
		return
	}
	expectedUserID, ok := pages[page]
	ret = a.validateUserID(username, expectedUserID)
	return
}

func (a *AccessData) validateUserID(username string, user_id int) bool {
	expectedUserID, ok := a.UserID[username]
	if !ok {
		if !a.S.Config.Force_UserID_validation {
			return true
		}
		return false
	}
	if expectedUserID == user_id || expectedUserID == -1 {
		return true
	}
	return false

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
