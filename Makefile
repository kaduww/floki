.PHONY: all build build-dev build-all run run-config clean install uninstall deps fmt vet test start stop restart status logs help reload

# Binary name
BINARY_NAME=floki
INSTALL_PATH=/usr/local/bin

# Paths
CMD_PKG=./src
CONF_SRC=configs/floki.conf
SERVICE_SRC=deploy/floki.service
INSTALL_SCRIPT=scripts/install.sh

# Build flags
LDFLAGS=-ldflags="-s -w"
BUILD_FLAGS=CGO_ENABLED=0 GOOS=linux

all: clean build

# Build the binary (production)
build:
	@echo "Building $(BINARY_NAME)..."
	@$(BUILD_FLAGS) go build $(LDFLAGS) -o $(BINARY_NAME) $(CMD_PKG)
	@echo "Build complete!"

# Build for development (with debug symbols)
build-dev:
	@echo "Building $(BINARY_NAME) in development mode..."
	@go build -o $(BINARY_NAME) $(CMD_PKG)
	@echo "Build complete!"

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 $(CMD_PKG)
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 $(CMD_PKG)
	@echo "Multi-platform build complete!"

# Run with the local config (development)
run: build-dev
	@echo "Running $(BINARY_NAME)..."
	@sudo ./$(BINARY_NAME) -config $(CONF_SRC)

# Run with a custom config path: make run-config CONFIG=/path/to/floki.conf
run-config: build-dev
	@echo "Running $(BINARY_NAME) with custom config..."
	@sudo ./$(BINARY_NAME) -config $(CONFIG)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME) $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-linux-arm64
	@go clean
	@echo "Clean complete!"

# Install via the install script
install:
	@sudo bash $(INSTALL_SCRIPT)

# Uninstall the binary and service
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo systemctl stop floki || true
	@sudo systemctl disable floki || true
	@sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@sudo rm -f /etc/systemd/system/floki.service
	@sudo systemctl daemon-reload
	@echo "Uninstall complete!"
	@echo "Note: /etc/floki/ was not removed"

# Download and tidy dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies updated!"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "Format complete!"

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "Vet complete!"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...
	@echo "Tests complete!"

# --- Service management ---

start:
	@sudo systemctl start floki

stop:
	@sudo systemctl stop floki

restart:
	@sudo systemctl restart floki

reload:
	@sudo systemctl reload floki

status:
	@sudo systemctl status floki

logs:
	@sudo journalctl -u floki -f

# Show help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build:"
	@echo "  build          Production binary (static, stripped)"
	@echo "  build-dev      Development binary (debug symbols)"
	@echo "  build-all      Linux amd64 + arm64 binaries"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Run:"
	@echo "  run            Build and run with configs/floki.conf"
	@echo "  run-config     Build and run with CONFIG=/path/to/floki.conf"
	@echo ""
	@echo "Install:"
	@echo "  install        Run scripts/install.sh"
	@echo "  uninstall      Remove binary and systemd service"
	@echo ""
	@echo "Development:"
	@echo "  deps           Download and tidy dependencies"
	@echo "  fmt            go fmt ./..."
	@echo "  vet            go vet ./..."
	@echo "  test           go test -v ./..."
	@echo ""
	@echo "Service:"
	@echo "  start          systemctl start floki"
	@echo "  stop           systemctl stop floki"
	@echo "  restart        systemctl restart floki"
	@echo "  reload         systemctl reload floki (SIGHUP)"
	@echo "  status         systemctl status floki"
	@echo "  logs           journalctl -u floki -f"
