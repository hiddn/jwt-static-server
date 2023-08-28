package debug

import "fmt"

var DEBUG = false

func Enable() {
	DEBUG = true
	LN("Debug enabled")
}
func Disable() {
	DEBUG = false
}

func IsEnabled() bool {
	return DEBUG
}

// Debugf is a wrapper function for fmt.Printf that adds the "Debug: " prefix
func F(format string, a ...any) (n int, err error) {
	if DEBUG != true {
		return
	}
	format = "Debug: " + format
	return fmt.Printf(format, a...)
}

// Debugln is a wrapper function for fmt.Println that adds the "Debug: " prefix
func LN(a ...interface{}) (n int, err error) {
	if DEBUG != true {
		return
	}
	if len(a) > 0 {
		a[0] = "Debug: " + fmt.Sprint(a[0])
	}
	return fmt.Println(a...)
}
