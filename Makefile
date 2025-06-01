all: build run

delete: 
	rm -rf bin
	rm -rf ./vilesql

build:
	delete
	go build -o vilesql main.go

run:
	./vilesql

dev: 
	CompileDaemon -build="go build -o vilesql main.go" -command="./vilesql"

ensure-compile-daemon:
	@which go > /dev/null || (echo "Error: Go is not installed or not in PATH" && exit 1)
	@which CompileDaemon > /dev/null || (echo "Installing CompileDaemon..." && go install github.com/githubnemo/CompileDaemon@latest)