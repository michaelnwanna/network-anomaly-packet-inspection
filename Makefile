.PHONY: build test check run clean

build:
	go build -trimpath -o bin/traceglass ./cmd/traceglass

test:
	go test -race ./...

check:
	go vet ./...
	go test -race ./...

run:
	go run ./cmd/traceglass serve

clean:
	go clean ./...
