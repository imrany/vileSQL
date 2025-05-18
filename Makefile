all: build run
dev: build ensure-compile-daemon watch

delete: 
	rm ./vilesql

build:
	go build -o vilesql main.go

run:
	./vilesql

watch: 
	ensure-compile-daemon
	CompileDaemon --command="./vilesql"

ensure-compile-daemon:
	@which go > /dev/null || (echo "Error: Go is not installed or not in PATH" && exit 1)
	@which CompileDaemon > /dev/null || (echo "Installing CompileDaemon..." && go install github.com/githubnemo/CompileDaemon@latest)