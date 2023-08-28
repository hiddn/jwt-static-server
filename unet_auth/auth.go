package unet_auth

import (
	"fmt"

	"github.com/hiddn/jwt-static-server/debug"
)

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
		if debug.IsEnabled() {
			fmt.Printf(" (default policy)")
		}
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
	if ok {
		ret = a.validateUserID(username, expectedUserID)
	}
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
