#!/bin/sh
version=$1

# turn to all lowercase and then capitalize the first letter of the OS name
os="$(uname -s | tr '[:upper:]' '[:lower:]' | awk '{ print toupper(substr($0, 1, 1)) substr($0, 2) }')"
arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

# there are two names for the same architecture
case "$arch" in
  aarch64) arch="arm64" ;;
esac

echo "Installing docker-shim"
echo "os: $os"
echo "arch: $arch"

# purposefully leaving the filename on the tar so that we know which shim was downloaded if we ever have to shell in and diagnose an issue
curl "https://github.com/Bandwidth/vault-shim/releases/download/v${version}/docker-shim_${os}_${arch}.tar.gz" --output "/usr/local/bin/docker-shim_${os}_${arch}.tar.gz"

tar xzf "/usr/local/bin/docker-shim_${os}_${arch}.tar.gz" -C "/usr/local/bin"
