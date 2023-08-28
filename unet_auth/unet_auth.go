package unet_auth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hiddn/jwt-static-server/confighandler"
	"github.com/hiddn/jwt-static-server/debug"
	"github.com/hiddn/jwt-static-server/jwtauth"
)

var sites []*Site

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

// Add a static site to serve
func Init(configFile string) {
	debug.Enable()
	var err error

	var s Site
	sites = append(sites, &s)
	s.Access.S = &s
	s.Config = confighandler.ReadConf(configFile)
	s.Access.DefaultPolicy = s.Config.Default_permission
	getJSONfromFile(configFile, &s.Config)

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
	http.HandleFunc("/logout", s.handleLogout)
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
	jwtTokens, err := jwtauth.GetJwtTokensFromCookie(r, s.Config.Cookie_name)
	if err != nil {
		fmt.Println("error with getJwtTokenFromCookie(): ", err)
	} else {
		//debug.LN("access token: ", jwtTokens.AccessToken)
		var isValid bool
		var claims jwt.MapClaims
		refresURL := fmt.Sprintf("%s%s", s.Config.Csc_api_url, s.Config.Csc_api_refresh_path)
		isValid, claims = s.Jwt.ValidateJWTTokens(w, jwtTokens, refresURL, s.Config.Cookie_name)
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
	// key: 'default' allows to set the default policy for the site
	// Accepted values: authed, deny, open, or <groupname>
	Page   string   `json:"page"`
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

func (s *Site) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(s.Config.Cookie_name)
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
