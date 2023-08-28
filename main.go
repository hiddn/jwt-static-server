package main

import "github.com/hiddn/jwt-static-server/unet_auth"

func main() {
	unet_auth.Init("config.json")
}
