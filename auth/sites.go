package auth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hiddn/jwt-static-server/jwtauth"
)

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

/*
// Unused for now
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
*/
