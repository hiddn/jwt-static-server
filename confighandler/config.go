package confighandler

type Configuration struct {
	Csc_api_url                string
	Csc_api_login_path         string
	Csc_api_refresh_path       string
	Csc_api_jwks_path          string
	Login_url                  string
	Login_content_serve_local  bool
	Login_content_dir          string
	Static_content_urlpath     string
	Static_content_dir         string
	Static_content_permissions string
	Pages_file                 string
	Groups_file                string
	Users_file                 string
	Force_UserID_validation    bool
}
