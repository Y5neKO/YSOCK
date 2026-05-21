APP_NAME := ysock
BUILD_DIR := build

.PHONY: build clean fmt vet

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/ysock/

clean:
	rm -rf $(BUILD_DIR)

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy
