#!/usr/bin/env bash
# Reads back what package.sh made, on the machine it was made for, and fails
# if anything an install relies on is wrong: the files and their modes and
# owners, the .deb's control file and libraries, the unit, and the
# maintainer scripts, which run here against stand-ins that only record what
# they were asked to do. Nothing is installed.
#
#   packaging/emberd/check-packages.sh 1.8.0 out
set -uo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION OUT_DIR" >&2
  exit 2
fi
version="$1"
out="$2"
case "$(uname -m)" in
  x86_64) arch=x86_64 deb_arch=amd64 ;;
  aarch64) arch=aarch64 deb_arch=arm64 ;;
  *) echo "emberd is not packaged for $(uname -m)" >&2; exit 2 ;;
esac

failed=0
check() {
  if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; failed=1; fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
name="emberd-$version-linux-$arch"
tarball="$out/$name.tar.gz"
deb="$out/emberd_${version}_${deb_arch}.deb"
if [ ! -f "$tarball" ] || [ ! -f "$deb" ]; then
  echo "FAIL $tarball and $deb are not both there" >&2
  exit 1
fi

echo "== $tarball"
tar -tzvf "$tarball" > "$work/tar.txt"
for f in emberd web/index.html resources/dbip-country-lite.mmdb emberd.toml emberd.service LICENSE; do
  check "has $f" "grep -q ' $name/$f\$' '$work/tar.txt'"
done
check "emberd is executable" "grep -qE '^-rwxr-xr-x .* $name/emberd\$' '$work/tar.txt'"
check "everything is owned by root" "! awk '{print \$2}' '$work/tar.txt' | grep -qv '^0/0\$'"
mkdir "$work/untar"
tar -C "$work/untar" -xzf "$tarball"
check "the emberd in it is $version" "[ \"\$('$work/untar/$name/emberd' --version)\" = 'emberd $version' ]"
if [ -d build-web ]; then
  check "it has every page" "diff -rq build-web '$work/untar/$name/web' >/dev/null"
fi

echo "== $deb"
dpkg-deb --contents "$deb" > "$work/contents.txt"
for f in ./opt/emberd/emberd ./opt/emberd/web/index.html ./opt/emberd/resources/dbip-country-lite.mmdb \
         ./usr/lib/systemd/system/emberd.service ./etc/emberd/emberd.toml ./usr/share/doc/emberd/copyright; do
  check "has $f" "grep -q ' $f\$' '$work/contents.txt'"
done
check "links /usr/bin/emberd to /opt/emberd/emberd" "grep -q ' ./usr/bin/emberd -> /opt/emberd/emberd\$' '$work/contents.txt'"
check "everything is owned by root" "! awk '{print \$2}' '$work/contents.txt' | grep -qv '^root/root\$'"
check "emberd is executable" "grep -qE '^-rwxr-xr-x .* ./opt/emberd/emberd\$' '$work/contents.txt'"
check "the config is not" "grep -qE '^-rw-r--r-- .* ./etc/emberd/emberd.toml\$' '$work/contents.txt'"
check "it is for $deb_arch" "[ \"\$(dpkg-deb --field '$deb' Architecture)\" = $deb_arch ]"
check "it is version $version" "[ \"\$(dpkg-deb --field '$deb' Version)\" = '$version' ]"
depends=$(dpkg-deb --field "$deb" Depends)
echo "   Depends: $depends"
check "it depends on a libc6 version" "grep -Eq 'libc6 \(>= 2\.[0-9]+\)' <<< '$depends'"
check "it depends on ca-certificates" "grep -q ca-certificates <<< '$depends'"
check "it depends on no D-Bus" "! grep -q dbus <<< '$depends'"
mkdir "$work/control" "$work/root"
dpkg-deb --control "$deb" "$work/control"
dpkg-deb -x "$deb" "$work/root"
check "the config is a conffile" "[ \"\$(cat '$work/control/conffiles')\" = /etc/emberd/emberd.toml ]"
check "the config is the repository's" "cmp -s packaging/emberd/emberd.toml '$work/root/etc/emberd/emberd.toml'"
check "the maintainer scripts are executable" "[ -x '$work/control/postinst' ] && [ -x '$work/control/prerm' ] && [ -x '$work/control/postrm' ]"
check "md5sums match every file" "(cd '$work/root' && md5sum --quiet -c '$work/control/md5sums') && [ \$(wc -l < '$work/control/md5sums') -eq \$(cd '$work/root' && find . -type f | wc -l) ]"
program="$work/root/opt/emberd/emberd"
libraries=$(readelf -d "$program" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')
echo "   links: $libraries"
check "emberd links glibc and libgcc alone" "[ -z \"\$(tr ' ' '\n' <<< '$libraries' | grep -v -e '^\$' -e '^libc\.so' -e '^libm\.so' -e '^libgcc_s\.so' -e '^ld-linux')\" ]"
newest=$(objdump -T "$program" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1)
echo "   newest glibc symbol: $newest"
check "it needs glibc 2.35 at most" "[ \"\$(printf '%s\n' GLIBC_2.35 '$newest' | sort -V | tail -n 1)\" = GLIBC_2.35 ]"

echo "== the unit"
sed "s#/opt/emberd/emberd#$program#" "$work/root/usr/lib/systemd/system/emberd.service" > "$work/emberd.service"
systemd-analyze verify "$work/emberd.service" > "$work/verify.txt" 2>&1
check "systemd reads it without complaint" "! grep 'emberd\.service' '$work/verify.txt' | grep -qvi -e 'user' -e 'group'"
grep 'emberd\.service' "$work/verify.txt" | sed 's/^/   /'

echo "== the maintainer scripts, against stand-ins"
for script in postinst prerm postrm; do
  check "$script is valid sh" "sh -n '$work/control/$script'"
  sed "s#/run/systemd/system#$work/systemd#; s#/var/lib/emberd#$work/state#g" "$work/control/$script" > "$work/$script"
  chmod +x "$work/$script"
done
mkdir "$work/stubs" "$work/systemd"
log="$work/calls.log"
for command in groupadd useradd systemctl; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$command" "$log" > "$work/stubs/$command"
done
printf '#!/bin/sh\n[ -e "%s/known" ]\n' "$work" > "$work/stubs/getent"
chmod +x "$work/stubs/"*
run() {
  : > "$log"
  PATH="$work/stubs:$PATH" "$work/$1" "${@:2}" > "$work/said.txt" 2>&1
}

run postinst configure ""
check "a first install makes the group and the user" "grep -qx 'groupadd --system emberd' '$log' && grep -q '^useradd --system --gid emberd --home-dir $work/state --no-create-home --shell /usr/sbin/nologin' '$log'"
check "a first install starts nothing" "grep -qx 'systemctl daemon-reload' '$log' && ! grep -qe start -e enable '$log'"
check "a first install says how to start it" "grep -q 'sudo systemctl enable --now emberd' '$work/said.txt'"
touch "$work/known"
run postinst configure 1.7.9
check "an upgrade makes no user" "! grep -qe useradd -e groupadd '$log'"
check "an upgrade restarts it only if it was running" "grep -qx 'systemctl try-restart emberd.service' '$log' && ! grep -qe ' start' -e enable '$log'"
check "an upgrade says nothing" "[ ! -s '$work/said.txt' ]"
run prerm upgrade 1.8.1
check "an upgrade leaves it running" "[ ! -s '$log' ]"
run prerm remove
check "a removal stops and disables it" "grep -qx 'systemctl stop emberd.service' '$log' && grep -qx 'systemctl disable emberd.service' '$log'"
mkdir "$work/state"
run postrm purge
check "a purge keeps the data and says where" "grep -q 'left in $work/state' '$work/said.txt' && [ -d '$work/state' ]"
rmdir "$work/systemd"
run postinst configure ""
check "without systemd, no systemctl" "! grep -q systemctl '$log'"

echo
if [ "$failed" -ne 0 ]; then
  echo "emberd's packages are not right" >&2
  exit 1
fi
echo "emberd's packages are right"
