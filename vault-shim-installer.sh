#!/bin/sh
version=$1

# turn to all lowercase and then capitalize the first letter of the OS name
os="$(uname -s | tr '[:upper:]' '[:lower:]' | awk '{ print toupper(substr($0, 1, 1)) substr($0, 2) }')"
arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

# there are two names for the same architecture
case "$arch" in
  aarch64) arch="arm64" ;;
esac

echo "Installing vault-shim version $version"
echo "os: $os"
echo "arch: $arch"

curl -L "https://github.com/Bandwidth/vault-shim/releases/download/v${version}/vault-shim_${os}_${arch}.tar.gz" --output "/usr/local/bin/vault-shim_${os}_${arch}.tar.gz"
tar xzf "/usr/local/bin/vault-shim_${os}_${arch}.tar.gz" -C "/usr/local/bin"
