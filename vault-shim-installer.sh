#!/bin/sh
git fetch --tags
latestTag=$(git describe --tags "$(git rev-list --tags --max-count=1)")

# turn to all lowercase and then capitalize the first letter of the OS name
os="$(uname -s | tr '[:upper:]' '[:lower:]' | awk '{ print toupper(substr($0, 1, 1)) substr($0, 2) }')"
arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

# there are two names for the same architecture
case "$arch" in
  aarch64) arch="arm64" ;;
esac

echo "Installing vault-shim"
echo "os: $os"
echo "arch: $arch"

# purposefully leaving the filename on the tar so that we know which shim was downloaded if we ever have to shell in and diagnose an issue
curl -L "https://github.com/Bandwidth/vault-shim/tarball/${latestTag}" --output "/usr/local/bin/vault-shim_${os}_${arch}.tar.gz"

tar xzf "/usr/local/bin/vault-shim_${os}_${arch}.tar.gz" -C "/usr/local/bin"
