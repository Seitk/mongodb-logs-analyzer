BINARY   := mla
CMD      := ./cmd/mla
DIST     := dist

GO       := go
GOFLAGS  :=
LDFLAGS  := -s -w

.PHONY: build test lint clean build-all

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

clean:
	rm -f $(BINARY)
	rm -rf $(DIST)

build-all: clean
	GOOS=darwin  GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-darwin-arm64 $(CMD)
	GOOS=linux   GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-linux-amd64  $(CMD)
	GOOS=linux   GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-linux-arm64  $(CMD)
