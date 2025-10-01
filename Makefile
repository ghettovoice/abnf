GINKGO_FLAGS=
GINKGO_BASE_FLAGS=-r --randomize-all -p --trace --race --vet=all --covermode=atomic --coverprofile=cover.profile
GINKGO_TEST_FLAGS=${GINKGO_BASE_FLAGS} --randomize-suites
GINKGO_WATCH_FLAGS=${GINKGO_BASE_FLAGS}

PKG_PATH=

setup:
	go mod tidy

build:
	go build -v -o ./out/abnf ./cmd/...

install:
	go install -v ./cmd/...

test:
	@go tool ginkgo version
	go tool ginkgo $(GINKGO_TEST_FLAGS) $(GINKGO_FLAGS) ./$(PKG_PATH)

watch:
	@go tool ginkgo version
	go tool ginkgo watch $(GINKGO_WATCH_FLAGS) $(GINKGO_FLAGS) ./$(PKG_PATH)

lint:
	go tool golangci-lint run -v ./...
	go tool govulncheck -version ./...

cov:
	go tool cover -html=./cover.profile

docs:
	go tool doc -http
