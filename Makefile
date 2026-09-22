GO          ?= go
MODULE      := github.com/w512/SysRail
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
LINUX_ENV   := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

TOOLS       := $(CURDIR)/build/tools
STATICCHECK := $(TOOLS)/staticcheck
GOVULNCHECK := $(TOOLS)/govulncheck

.PHONY: all build build-linux test vet fmt-check staticcheck vulncheck check test-remote clean

all: check build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o build/sysrail ./cmd/sysrail

build-linux:
	$(LINUX_ENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o build/linux-amd64/sysrail ./cmd/sysrail

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...
	$(LINUX_ENV) $(GO) vet -tags integration ./...

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

$(STATICCHECK):
	GOBIN=$(TOOLS) $(GO) install honnef.co/go/tools/cmd/staticcheck@v0.8.1

$(GOVULNCHECK):
	GOBIN=$(TOOLS) $(GO) install golang.org/x/vuln/cmd/govulncheck@v1.8.0

# Tools are built for the host; GOOS only selects which files are analyzed.
staticcheck: $(STATICCHECK)
	$(STATICCHECK) ./...
	$(LINUX_ENV) $(STATICCHECK) -tags integration ./...

vulncheck: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

check: fmt-check vet staticcheck test

# Cross-compiles test binaries (with the integration tag) and runs them on the
# Linux test host. See scripts/test-remote.sh for knobs.
test-remote:
	./scripts/test-remote.sh

clean:
	rm -rf build
