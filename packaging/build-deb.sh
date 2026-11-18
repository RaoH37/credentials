#!/bin/sh
# Construit dist/credentials_<version>_<arch>.deb
# Usage : VERSION=1.2.0 ARCH=amd64 packaging/build-deb.sh
set -eu
umask 022
cd "$(dirname "$0")/.."

VERSION=${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)}
VERSION=${VERSION:-0.1.0}
ARCH=${ARCH:-$(dpkg --print-architecture)}
MAINTAINER=${MAINTAINER:-"$(git config user.name 2>/dev/null || echo credentials) <$(git config user.email 2>/dev/null || echo root@localhost)>"}

case "$ARCH" in
amd64|arm64|riscv64) GOARCH=$ARCH ;;
armhf) GOARCH=arm; export GOARM=7 ;;
i386) GOARCH=386 ;;
*) echo "architecture non gérée : $ARCH" >&2; exit 1 ;;
esac

PKG=dist/credentials_${VERSION}_${ARCH}
rm -rf "$PKG" "$PKG.deb"
mkdir -p "$PKG/DEBIAN"

echo "==> compilation $VERSION ($ARCH)"
CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -trimpath \
	-ldflags "-s -w -X main.version=$VERSION" -o "$PKG/usr/bin/credentials" .

install -D -m 0644 packaging/credentials.service "$PKG/usr/lib/systemd/system/credentials.service"
install -D -m 0644 packaging/sysusers.conf       "$PKG/usr/lib/sysusers.d/credentials.conf"
install -D -m 0755 packaging/encrypt-passphrase  "$PKG/usr/lib/credentials/encrypt-passphrase"
install -D -m 0755 packaging/credentials-passphrase "$PKG/usr/sbin/credentials-passphrase"
install -D -m 0644 packaging/config.toml         "$PKG/etc/credentials/config.toml"
install -D -m 0644 README.md                     "$PKG/usr/share/doc/credentials/README.md"

sed -e "s|@VERSION@|$VERSION|" -e "s|@ARCH@|$ARCH|" -e "s|@MAINTAINER@|$MAINTAINER|" \
	packaging/debian/control.in > "$PKG/DEBIAN/control"
echo "Installed-Size: $(du -sk --exclude=DEBIAN "$PKG" | cut -f1)" >> "$PKG/DEBIAN/control"
install -m 0644 packaging/debian/conffiles packaging/debian/templates "$PKG/DEBIAN/"
install -m 0755 packaging/debian/config packaging/debian/postinst \
	packaging/debian/prerm packaging/debian/postrm "$PKG/DEBIAN/"

dpkg-deb --root-owner-group -Zxz --build "$PKG" "$PKG.deb" >/dev/null
rm -rf "$PKG"
echo "==> $PKG.deb"
