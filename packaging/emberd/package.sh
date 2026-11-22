#!/usr/bin/env bash
# Packages a release build of emberd for Linux, as release.yml does: the
# tarball, which is /opt/emberd unpacked by hand and what the Docker image is
# made from, and the .deb, which installs the same files with the systemd unit
# and the emberd user. From the repository root, after `npm run build:web` and
# `cargo build --release --no-default-features --features server --bin emberd`:
#
#   packaging/emberd/package.sh 1.8.0 out
#
# EMBERD_BINARY and EMBERD_WEB name a build elsewhere. The machine is read from
# the binary, so the packages are named for what it runs on.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION OUT_DIR" >&2
  exit 2
fi
version="$1"
out="$2"
binary="${EMBERD_BINARY:-src-tauri/target/release/emberd}"
web="${EMBERD_WEB:-build-web}"
here="$(cd "$(dirname "$0")" && pwd)"
geoip="src-tauri/resources/dbip-country-lite.mmdb"

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "not a version: $version" >&2
  exit 2
fi
for file in "$binary" "$web/index.html" "$geoip" LICENSE; do
  if [ ! -f "$file" ]; then
    echo "$file is missing; build emberd and the web interface first, from the repository root" >&2
    exit 1
  fi
done

case "$(readelf -h "$binary" | sed -n 's/^ *Machine: *//p')" in
  *X86-64*) arch=x86_64 deb_arch=amd64 ;;
  AArch64) arch=aarch64 deb_arch=arm64 ;;
  *)
    echo "$binary is for a machine emberd is not packaged for" >&2
    exit 1
    ;;
esac
if [ "$arch" = "$(uname -m)" ]; then
  said="$("$binary" --version)"
  if [ "$said" != "emberd $version" ]; then
    echo "$binary says it is \"$said\", not emberd $version" >&2
    exit 1
  fi
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$out"

# The files emberd runs with, under `root`: the program, the pages, and the
# country database, as `resource_dir` finds them beside the program.
place() {
  local root="$1"
  install -Dm755 "$binary" "$root/emberd"
  mkdir -p "$root/web"
  cp -R "$web/." "$root/web/"
  install -Dm644 "$geoip" "$root/resources/dbip-country-lite.mmdb"
}

name="emberd-${version}-linux-${arch}"
place "$stage/$name"
install -m644 "$here/emberd.toml" "$here/emberd.service" LICENSE "$stage/$name/"
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner -czf "$out/$name.tar.gz" "$name"

deb="$stage/deb"
place "$deb/opt/emberd"
mkdir -p "$deb/usr/bin"
ln -s /opt/emberd/emberd "$deb/usr/bin/emberd"
install -Dm644 "$here/emberd.service" "$deb/usr/lib/systemd/system/emberd.service"
install -Dm644 "$here/emberd.toml" "$deb/etc/emberd/emberd.toml"
install -Dm644 LICENSE "$deb/usr/share/doc/emberd/copyright"
install -d "$deb/DEBIAN"
for script in postinst prerm postrm; do
  install -m755 "$here/deb/$script" "$deb/DEBIAN/$script"
done
echo /etc/emberd/emberd.toml > "$deb/DEBIAN/conffiles"
(cd "$deb" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | sort -z | xargs -0 md5sum) > "$deb/DEBIAN/md5sums"

# The libraries emberd links, as the versions of the packages that hold them.
# dpkg-shlibdeps wants a source package around it, which an empty
# debian/control is enough to stand in for.
mkdir -p "$stage/debian"
touch "$stage/debian/control"
libraries="$(cd "$stage" && dpkg-shlibdeps -O -e deb/opt/emberd/emberd 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
if [ -z "$libraries" ]; then
  echo "dpkg-shlibdeps found no libraries for $binary" >&2
  exit 1
fi

cat > "$deb/DEBIAN/control" <<EOF
Package: emberd
Version: $version
Architecture: $deb_arch
Maintainer: untaimed18 <26585786+untaimed18@users.noreply.github.com>
Installed-Size: $(du -sk --exclude=DEBIAN "$deb" | cut -f1)
Depends: $libraries, ca-certificates, passwd
Section: net
Priority: optional
Homepage: https://www.emberp2p.org/
Description: Ember P2P file sharing, without a window
 emberd runs Ember on a server with no screen: eD2K servers, Kad, the Ember
 network, search, downloads and sharing, friends, chat and rooms, driven
 from a web browser behind a password.
 .
 It installs as a systemd service that is not started until you start it.
EOF
dpkg-deb --root-owner-group -Zxz --build "$deb" "$out/emberd_${version}_${deb_arch}.deb" >/dev/null

echo "$out/$name.tar.gz"
echo "$out/emberd_${version}_${deb_arch}.deb"
