PKG_PATH=...

setup:
	go mod tidy

build:
	go build -v -o ./out/abnf ./cmd/...

install:
	go install -v ./cmd/...

test:
	go test -vet=all -covermode=atomic -coverprofile=cover.out ./$(PKG_PATH)

lint:
	go tool golangci-lint run -v ./...
	go tool govulncheck -version ./...

cov:
	go tool cover -html=./cover.out

docs:
	go tool doc -http
