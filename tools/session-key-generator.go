package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateSessionKey(length int) (string, error) {
	randomBytes, err := generateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

func main() {
	sessionKey, err := generateSessionKey(32) // Adjust the length as needed
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	fmt.Println("Generated Session Key:", sessionKey)
}
