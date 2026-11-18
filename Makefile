VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo 0.1.0)

.PHONY: build deb install clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(or $(VERSION),dev)" -o credentials .

deb:
	VERSION=$(VERSION) packaging/build-deb.sh

install: deb
	sudo apt install ./dist/credentials_$(or $(VERSION),0.1.0)_$(shell dpkg --print-architecture).deb

clean:
	rm -rf credentials dist
