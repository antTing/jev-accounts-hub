.PHONY: run build mcp test tidy docker

run:
	go run ./cmd/jevproxy

build:
	go build -ldflags "-s -w" -o jevproxy ./cmd/jevproxy

mcp:
	go run ./cmd/jev-mcp

test:
	go test ./...

tidy:
	go mod tidy

docker:
	docker compose up --build
