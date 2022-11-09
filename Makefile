VERSION=$(shell git describe --tags)
LDFLAGS=
GOFLAGS=

GINKGO_FLAGS=
GINKGO_BASE_FLAGS=-r --randomize-all -p --trace --race --vet=all --covermode=atomic --coverprofile=cover.profile --progress
GINKGO_TEST_FLAGS=${GINKGO_BASE_FLAGS} --randomize-suites
GINKGO_WATCH_FLAGS=${GINKGO_BASE_FLAGS}

PKG_PATH=

install:
	go get -v -t ./...
	go install -mod=mod github.com/onsi/ginkgo/v2/ginkgo

test:
	ginkgo version
	ginkgo $(GINKGO_TEST_FLAGS) $(GINKGO_FLAGS) $(GOFLAGS) ./$(PKG_PATH)

watch:
	ginkgo version
	ginkgo watch $(GINKGO_WATCH_FLAGS) $(GINKGO_FLAGS) $(GOFLAGS) ./$(PKG_PATH)

cover-report:
	go tool cover -html=./cover.profile

doc:
	@echo "Running documentation on http://localhost:8080/github.com/ghettovoice/abnf"
	pkgsite -http=localhost:8080
