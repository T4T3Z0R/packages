#!/usr/bin/env bash
set -euo pipefail

: "${PACKAGE_NAME:?PACKAGE_NAME is required}"
: "${PACKAGE_FILE:?PACKAGE_FILE is required}"

if [[ ! "$PACKAGE_NAME" =~ ^[a-z][a-z0-9-]*$ ]]; then
  echo "Invalid PACKAGE_NAME: $PACKAGE_NAME" >&2
  exit 1
fi

if [[ ! "$PACKAGE_FILE" =~ ^[a-zA-Z0-9._+-]+[.]pkg[.]tar[.]zst$ ]]; then
  echo "Invalid PACKAGE_FILE: $PACKAGE_FILE" >&2
  exit 1
fi

candidate="package-output/$PACKAGE_FILE"
test -f "$candidate"
test -f "${candidate}.sig"

candidate_name="$(
  bsdtar -xOf "$candidate" .PKGINFO |
    sed -n "s/^pkgname = //p"
)"

if [[ "$candidate_name" != "$PACKAGE_NAME" ]]; then
  echo "Candidate package identity mismatch" >&2
  exit 1
fi

gpg --verify "${candidate}.sig" "$candidate"

mkdir -p repo-output

# The rolling repository must already exist. A GitHub/API error
# must never masquerade as an empty repository.
gh release view "$RELEASE_TAG" >/dev/null

gh release download "$RELEASE_TAG" \
  --pattern '*.pkg.tar.zst' \
  --pattern '*.pkg.tar.zst.sig' \
  --dir repo-output

# Verify every package already trusted by the repository before
# using it to construct the next repository state.
shopt -s nullglob
existing_packages=( repo-output/*.pkg.tar.zst )

for existing_pkg in "${existing_packages[@]}"; do
  existing_sig="${existing_pkg}.sig"

  if [[ ! -f "$existing_sig" ]]; then
    echo "Existing repository package lacks signature: $existing_pkg" >&2
    exit 1
  fi

  gpg --verify "$existing_sig" "$existing_pkg"
done

# Remove only versions of the selected package.
for existing_pkg in "${existing_packages[@]}"; do
  existing_name="$(
    bsdtar -xOf "$existing_pkg" .PKGINFO |
      sed -n "s/^pkgname = //p"
  )"

  if [[ "$existing_name" == "$PACKAGE_NAME" ]]; then
    rm -f "$existing_pkg" "${existing_pkg}.sig"
  fi
done

cp "package-output/${PACKAGE_FILE}" repo-output/
cp "package-output/${PACKAGE_FILE}.sig" repo-output/

cd repo-output

shopt -s nullglob
packages=( *.pkg.tar.zst )

if (( ${#packages[@]} == 0 )); then
  echo "No Pacman packages available for repository database" >&2
  exit 1
fi

repo-add \
  --include-sigs \
  "${REPO_NAME}.db.tar.zst" \
  "${packages[@]}"

rm -f "${REPO_NAME}.db" "${REPO_NAME}.files"

cp -L "${REPO_NAME}.db.tar.zst" "${REPO_NAME}.db"
cp -L "${REPO_NAME}.files.tar.zst" "${REPO_NAME}.files"

rm -f \
  "${REPO_NAME}.db.tar.zst" \
  "${REPO_NAME}.files.tar.zst"

sign_file() {
  local file="$1"

  printf '%s' "$ARCH_REPO_SIGNING_PASSPHRASE" \
    | gpg \
        --batch \
        --yes \
        --pinentry-mode loopback \
        --passphrase-fd 0 \
        --local-user "${SIGNING_SUBKEY}!" \
        --output "${file}.sig" \
        --detach-sign \
        "$file"

  gpg --verify "${file}.sig" "$file"
}

sign_file "${REPO_NAME}.db"
sign_file "${REPO_NAME}.files"

cp \
  "$GITHUB_WORKSPACE/arch/keys/t4t3z0r-package-signing.asc" \
  .

mapfile -d '' checksum_files < <(
  find . \
    -maxdepth 1 \
    -type f \
    ! -name SHA256SUMS \
    -printf '%f\0' \
    | sort -z
)

if (( ${#checksum_files[@]} == 0 )); then
  echo "No repository assets available for checksums" >&2
  exit 1
fi

sha256sum "${checksum_files[@]}" \
  > SHA256SUMS
