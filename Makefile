all: build genkey
build:
	go build .
genkey:
	go build -o session-key-generator ./tools/session-key-generator.go
