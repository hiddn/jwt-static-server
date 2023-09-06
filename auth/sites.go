package auth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hiddn/jwt-static-server/debug"
	"github.com/hiddn/jwt-static-server/jwtlib"
)

func (s *Site) HandleRefreshCB(w http.ResponseWriter, r *http.Request, jwtTokens jwtlib.JwtTokens) {
	s.SetSessionValue(w, r, "access_token", jwtTokens.AccessToken)
	cookieName := s.Config.Jwt_cookie_name
	jwtlib.SetJwtCookie(w, cookieName, jwtTokens.RefreshToken)
}

func (s Site) serveStatic(w http.ResponseWriter, r *http.Request) {
	var fs http.Handler
	servePage := func() {
		realHandler := http.StripPrefix(s.Config.Static_content_urlpath, fs).ServeHTTP
		realHandler(w, r)
	}
	var loginErrStr string = ""
	fs = http.FileServer(http.Dir(s.Config.Static_content_dir))
	if s.Access.DefaultPolicy == "open" {
		fmt.Printf("(policy: open): serving %s without authentification\n", r.URL.Path)
		servePage()
		return
	}
	accessToken := s.GetSessionValue(w, r, "access_token")
	if accessToken != "" {
		//debug.LN("access token: ", jwtTokens.AccessToken)
		var isValid bool = false
		var claims jwt.MapClaims
		refreshURL := fmt.Sprintf("%s%s", s.Config.Csc_api_url, s.Config.Csc_api_refresh_path)
		isValid, claims = s.Jwt.ValidateAccessToken(w, r, accessToken, refreshURL, s.Config.Jwt_cookie_name, s.HandleRefreshCB)
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
	s.RedirectToLoginPage(w, r, loginErrStr)
	return
}

func (s *Site) RedirectToLoginPage(w http.ResponseWriter, r *http.Request, loginErrStr string) {
	var fullURL string
	var path string
	if r.URL.String() == "/logout" {
		path = s.Config.Static_content_urlpath
	} else {
		path = r.URL.String()
	}
	fullURL = s.Config.Site_url + path
	debug.F("fullURL = %s\n", fullURL)
	login_path := fmt.Sprintf("%s?next=%s%s", s.Config.Login_url, url.QueryEscape(fullURL), loginErrStr)
	http.Redirect(w, r, login_path, http.StatusSeeOther)
}

func (s *Site) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(s.Config.Jwt_cookie_name)
	var loginErrStr string
	if err == nil {
		c.Expires = time.Unix(1414414788, 1414414788000)
		http.SetCookie(w, c)
		loginErrStr = "You are now logged out"
	} else {
		loginErrStr = "You were already logged out"
	}
	if loginErrStr != "" {
		loginErrStr = fmt.Sprintf("&message=%s", url.QueryEscape(loginErrStr))
	}
	s.EndSession(w, r)
	s.RedirectToLoginPage(w, r, loginErrStr)
}

func (s *Site) handleSetJwtTokens(w http.ResponseWriter, r *http.Request) {
	// Now receiving as form data instead of json anymore, to avoid preflight.
	// For CORS, it will be considered a safe request if:
	//		1. Safe method is used: GET, POST or HEAD (nothing else)
	//		2. Safe headers.
	//			- Content-Type with the value application/x-www-form-urlencoded, multipart/form-data or text/plain.
	//			- Only other accepted Headers: Accept, Accept-Language, Content-Language
	// Ref.: https://javascript.info/fetch-crossorigin#cors-for-safe-requests

	r.ParseForm()
	accessToken := r.FormValue("access_token")
	refreshToken := r.FormValue("refresh_token")
	//debug.F("handleSetJwtCookie():\n\tat: %v\n\trt: %v\n", accessToken, refreshToken)
	if accessToken == "" || refreshToken == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	cookieName := s.Config.Jwt_cookie_name
	jwtlib.SetJwtCookie(w, cookieName, refreshToken)
	s.SetSessionValue(w, r, "access_token", accessToken)
}

func (s *Site) SetSessionValue(w http.ResponseWriter, r *http.Request, key, accessToken string) {
	// Get a session. We're ignoring the error resulted from decoding an
	// existing session: Get() always returns a session, even if empty.
	session, _ := s.Store.Get(r, s.Config.Session_name)
	session.Values[key] = accessToken
	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Site) EndSession(w http.ResponseWriter, r *http.Request) {
	// Get a session. We're ignoring the error resulted from decoding an
	// existing session: Get() always returns a session, even if empty.
	session, _ := s.Store.Get(r, s.Config.Session_name)
	session.Options.MaxAge = -1
	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Site) GetSessionValue(w http.ResponseWriter, r *http.Request, accessToken string) string {
	var rt string
	var ok bool

	// Get a session. We're ignoring the error resulted from decoding an
	// existing session: Get() always returns a session, even if empty.
	session, _ := s.Store.Get(r, s.Config.Session_name)
	rt, ok = session.Values["access_token"].(string)
	if !ok {
		return ""
	}
	return rt
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
