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

help:
	@echo "Makefile commands:"
	@echo "  all: Build and run the application"
	@echo "  delete: Remove build artifacts"
	@echo "  build: Compile the application"
	@echo "  run: Execute the compiled application"
	@echo "  dev: Start development mode with hot reloading"
	@echo "  ensure-compile-daemon: Ensure CompileDaemon is installed"
	@echo "  help: Display this help message"