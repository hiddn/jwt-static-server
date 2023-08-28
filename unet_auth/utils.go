package unet_auth

import (
	"encoding/json"
	"log"
	"os"
)

func getJSONfromFile(file string, ptr interface{}) {
	content, err := os.ReadFile(file)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}
	if err := json.Unmarshal(content, &ptr); err != nil {
		log.Fatalf("getJSONfromFile() error with %s: %s", file, err)
	}
}
