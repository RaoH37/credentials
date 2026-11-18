VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
DEB_ARCH := $(shell dpkg --print-architecture 2>/dev/null)

.PHONY: build test vet check deb install clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(or $(VERSION),dev)" -o credentials ./cmd/credentials

test:
	go test -race -count=1 ./...

vet:
	gofmt -l . | (! grep .) || (echo "run gofmt -w ." && false)
	go vet ./...

check: vet test

deb:
	VERSION=$(VERSION) packaging/build-deb.sh

install: deb
	sudo apt install ./dist/credentials_$(or $(VERSION),0.1.0)_$(DEB_ARCH).deb

clean:
	rm -rf credentials dist
