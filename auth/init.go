package auth

import (
	"fmt"
	"log"
	"net/http"

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
	var err error

	var s Site
	sites = append(sites, &s)
	s.Access.S = &s
	s.Config = confighandler.ReadConf(configFile)
	if s.Config.Enable_debug == true {
		debug.Enable()
	}
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

func (a *AccessData) LoadUsersAndPages(pages_file, groups_file, users_file string) {
	a.DefaultPolicy = a.S.Config.Default_permission
	getJSONfromFile(users_file, &a.UserID)
	getJSONfromFile(pages_file, &a.PageGroups)
	getJSONfromFile(groups_file, &a.GroupUsers)

	fmt.Println("Default policy:", a.DefaultPolicy)
	a.buildAccessMapByUser()
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
