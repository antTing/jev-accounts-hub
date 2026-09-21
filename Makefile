.PHONY: run build test tidy docker

run:
	go run ./cmd/jevproxy

build:
	go build -ldflags "-s -w" -o jevproxy ./cmd/jevproxy

test:
	go test ./...

tidy:
	go mod tidy

docker:
	docker compose up --build
