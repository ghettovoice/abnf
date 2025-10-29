PKG=...

setup:
	go mod tidy

build:
	go build -o ./out/abnf ./cmd/...

install:
	go install ./cmd/...

test:
	go test -race -vet=all -covermode=atomic -coverprofile=cover.out ./$(PKG)

lint:
	go tool golangci-lint run ./...
	go tool govulncheck ./...

cov:
	go tool cover -html=./cover.out

docs:
	go tool doc -http

# Release a new version
# Usage: make release VERSION=vX.Y.Z
release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is not set. Usage: make release VERSION=vX.Y.Z" >&2; \
		exit 1; \
	fi
	@if ! echo "$(VERSION)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$$'; then \
		echo "Error: Invalid version format. Use semantic versioning (e.g., v1.2.3, v1.2.3-alpha.1, v1.2.3-beta.2, v1.2.3-rc.3)" >&2; \
		exit 1; \
	fi
	@echo "Updating version to $(VERSION) in abnf.go..."
	@sed -i '' 's/^const VERSION = ".*"/const VERSION = "$(VERSION)"/' abnf.go
	git add abnf.go
	git commit -m "Release $(VERSION)"
	git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "\nRelease $(VERSION) is ready to be pushed. Run the following command to publish:"
	@echo "  git push --follow-tags"

bench: PKG=
bench:
	$(eval PREFIX := $(shell if [ "$(PKG)" = "..." ] || [ "$(PKG)" = "." ] || [ "$(PKG)" = "" ]; then echo "abnf_"; else echo "$(PKG)" | sed 's#/#_#g'; fi ))
	$(eval SUFFIX := $(shell echo "_$(shell date +%Y%m%d%H%M%S)"))
	go test -vet=all -run=^$$ -bench=. -benchmem -count=10 \
		-memprofile=$(PREFIX)mem$(SUFFIX).out \
		-cpuprofile=$(PREFIX)cpu$(SUFFIX).out \
		./$(PKG) \
	| tee $(PREFIX)bench$(SUFFIX).out
