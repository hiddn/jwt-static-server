package main

import "github.com/hiddn/jwt-static-server/auth"

func main() {
	auth.Init("config.json")
}
