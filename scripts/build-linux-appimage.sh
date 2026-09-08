#!/usr/bin/env bash
# Build an unsigned Linux AppImage from a WSL (or native Linux) shell.
#
# This exists so the rebuild is one short command typed into WSL instead of a
# multi-line paste. Pasting is the thing it replaces: continuation backslashes
# collapse into half a command, and text copied on Windows arrives with CRLF
# line endings, which bash reports as `$'\r': command not found`.
#
#   bash /mnt/c/P2PApp/scripts/build-linux-appimage.sh     # from the Windows tree
#   bash scripts/build-linux-appimage.sh                   # from a Linux clone
#
# When the repository holding this script is on a Windows drive (/mnt/...), it
# deliberately does not build there: drvfs is slow enough to dominate the build,
# and the Windows-side toolchain and this one would share a single
# src-tauri/target. It syncs a Linux-native work tree instead (default ~/ember)
# and builds in that, then copies the artifact back to release-out/ on the
# Windows side, which .gitignore already covers.
#
# Usage:
#   bash scripts/build-linux-appimage.sh [branch]      # branch default: develop
# Environment:
#   EMBER_LINUX_TREE   Linux work tree to build in     (default: ~/ember)
#   EMBER_BUNDLES      value passed to --bundles        (default: appimage)

set -euo pipefail

branch="${1:-develop}"
bundles="${EMBER_BUNDLES:-appimage}"
work_tree="${EMBER_LINUX_TREE:-$HOME/ember}"

script_dir="$(cd "$(dirname "$0")" && pwd)"
source_repo="$(cd "$script_dir/.." && pwd)"

case "$source_repo" in
  /mnt/*) on_windows_drive=1 ;;
  *) on_windows_drive=0 ;;
esac

# Fail before the compile rather than after it. The first hand-built AppImage
# spent ten minutes compiling and then died on a missing `xdg-mime`, which the
# bundler shells out to for the .emulecollection file association.
apt_missing=()
command -v node >/dev/null 2>&1 || apt_missing+=("nodejs")
command -v npm >/dev/null 2>&1 || apt_missing+=("npm")
command -v xdg-mime >/dev/null 2>&1 || apt_missing+=("xdg-utils")
command -v pkg-config >/dev/null 2>&1 || apt_missing+=("pkg-config")
command -v file >/dev/null 2>&1 || apt_missing+=("file")
if command -v pkg-config >/dev/null 2>&1; then
  pkg-config --exists webkit2gtk-4.1 || apt_missing+=("libwebkit2gtk-4.1-dev")
  pkg-config --exists gtk+-3.0 || apt_missing+=("libgtk-3-dev")
fi

if (( ${#apt_missing[@]} > 0 )); then
  echo "error: missing build dependencies. Install them with:" >&2
  echo >&2
  echo "  sudo apt-get update && sudo apt-get install -y ${apt_missing[*]}" >&2
  echo >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not on PATH. Install Rust (1.94+) with:" >&2
  echo >&2
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" >&2
  echo "  . \"\$HOME/.cargo/env\"" >&2
  echo >&2
  exit 1
fi

if (( on_windows_drive )); then
  # WSL sees the Windows tree as owned by someone else, so git refuses to read
  # it until the path is marked safe.
  #
  # `git -c safe.directory=...` does not achieve that here, and neither do the
  # GIT_CONFIG_* environment variables: reading a local source repository goes
  # through an `upload-pack` child process, and the exception does not reach it.
  # Overriding that child command is what works. It also keeps the exception
  # scoped to this one invocation rather than writing a permanent entry into the
  # user's --global config, which is what git's own error message suggests.
  upload_pack="git -c safe.directory=$source_repo/.git upload-pack"

  if [[ ! -d "$work_tree/.git" ]]; then
    echo "==> cloning $source_repo into $work_tree"
    git clone --upload-pack="$upload_pack" "$source_repo" "$work_tree"
  fi

  # The sync below resets the work tree onto the source branch, so anything
  # uncommitted there would be lost. It is a build tree, but say so rather than
  # discarding someone's debugging.
  if [[ -n "$(git -C "$work_tree" status --porcelain)" ]]; then
    echo "error: $work_tree has uncommitted changes; commit or discard them first" >&2
    exit 1
  fi

  echo "==> syncing $work_tree to $branch"
  git -C "$work_tree" fetch --upload-pack="$upload_pack" "$source_repo" "$branch"
  git -C "$work_tree" checkout -B "$branch" FETCH_HEAD
  build_root="$work_tree"
else
  build_root="$source_repo"
fi

cd "$build_root"

if [[ ! -d node_modules ]]; then
  echo "==> installing frontend dependencies"
  npm ci
fi

# `createUpdaterArtifacts` is true in tauri.conf.json for the signed Windows
# release. There is no signing key here, so leaving it on would fail the bundle
# after the whole compile had already been paid for.
#
# APPIMAGE_EXTRACT_AND_RUN because the bundler runs linuxdeploy, which is itself
# an AppImage and therefore wants FUSE. This avoids needing libfuse2 installed
# just to produce a build.
echo "==> building ($bundles) in $build_root"
build_started_at="$(date +%s)"
APPIMAGE_EXTRACT_AND_RUN=1 npm run tauri build -- \
  --bundles "$bundles" \
  --config '{"bundle":{"createUpdaterArtifacts":false}}'

# Only what this run produced. target/ is not cleaned between builds, so an
# earlier bundle of a different format sits there indefinitely — and copying it
# out gives it a fresh mtime on the Windows side, which is how a stale artifact
# gets handed to a tester as if it were the current one.
bundle_dir="$build_root/src-tauri/target/release/bundle"
mapfile -t artifacts < <(
  find "$bundle_dir" -type f \
    \( -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' \) \
    -newermt "@$build_started_at" | sort
)

if (( ${#artifacts[@]} == 0 )); then
  echo "error: the build reported success but produced no new bundle under" >&2
  echo "       $bundle_dir" >&2
  exit 1
fi

echo
echo "built:"
for artifact in "${artifacts[@]}"; do
  echo "  $artifact"
done

if (( on_windows_drive )); then
  out_dir="$source_repo/release-out"
  mkdir -p "$out_dir"
  cp -f "${artifacts[@]}" "$out_dir/"
  echo
  echo "copied to the Windows side:"
  if command -v wslpath >/dev/null 2>&1; then
    echo "  $(wslpath -w "$out_dir")"
  else
    echo "  $out_dir"
  fi
fi

echo
echo "Reminder for a Debian 13 / LMDE 7 tester: FUSE 2 is not installed there by"
echo "default and was renamed, so they need 'sudo apt install libfuse2t64', or"
echo "they can run it with APPIMAGE_EXTRACT_AND_RUN=1 and install nothing."
