#!/usr/bin/env bash
set -euo pipefail

: "${PACKAGE_NAME:?PACKAGE_NAME is required}"
: "${PACKAGE_FILE:?PACKAGE_FILE is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${REPO_NAME:?REPO_NAME is required}"
: "${SIGNING_SUBKEY:?SIGNING_SUBKEY is required}"
: "${ARCH_REPO_SIGNING_PASSPHRASE:?Signing passphrase is required}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

# A failed assembly must never leave old staging or success state.
rm -f archive-state.txt
rm -rf -- archive-output

if [[ ! "$SIGNING_SUBKEY" =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "SIGNING_SUBKEY must be a full 40-character fingerprint" >&2
  exit 1
fi

SIGNING_SUBKEY="${SIGNING_SUBKEY^^}"

# Verify configured signer against the repository public key.
public_key="$GITHUB_WORKSPACE/arch/keys/t4t3z0r-package-signing.asc"

if [[ ! -f "$public_key" ]]; then
  echo "Repository signing public key is missing" >&2
  exit 1
fi

if ! key_records="$(gpg --batch --with-colons --show-keys "$public_key")"; then
  echo "Unable to inspect repository signing public key" >&2
  exit 1
fi

if ! printf "%s\\n" "$key_records" |
    grep "^fpr:" |
    cut -d: -f10 |
    grep -Fxiq -- "$SIGNING_SUBKEY"; then
  echo "Configured signing fingerprint does not match repository public key" >&2
  exit 1
fi

verify_signed_file() {
  local signature="$1"
  local payload="$2"
  local status prefix marker signer remainder
  local matches=0

  if ! status="$(gpg --batch --status-fd 1 --verify "$signature" "$payload" 2>/dev/null)"; then
    echo "GPG verification failed: $payload" >&2
    return 1
  fi

  while read -r prefix marker signer remainder; do
    if [[ "$prefix" == "[GNUPG:]" && "$marker" == "VALIDSIG" ]]; then
      matches=$((matches + 1))
      if [[ "${signer^^}" != "$SIGNING_SUBKEY" ]]; then
        echo "Unauthorized signing fingerprint: $payload" >&2
        return 1
      fi
    fi
  done <<< "$status"

  if (( matches != 1 )); then
    echo "Expected exactly one valid signature: $payload" >&2
    return 1
  fi
}

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

verify_signed_file "${candidate}.sig" "$candidate"

# Optional additional packages from the same validated build.
candidate_files=("$PACKAGE_FILE")
candidate_names=("$PACKAGE_NAME")

declare -A selected_names=()
selected_names["$PACKAGE_NAME"]=1

if [[ -n "${ADDITIONAL_PACKAGE_FILES:-}" ]]; then
  if [[ ! "$ADDITIONAL_PACKAGE_FILES" =~ ^[A-Za-z0-9._+-]+[.]pkg[.]tar[.]zst([ ]+[A-Za-z0-9._+-]+[.]pkg[.]tar[.]zst)*$ ]]; then
    echo "Invalid ADDITIONAL_PACKAGE_FILES" >&2
    exit 1
  fi

  read -r -a extra_files <<< "$ADDITIONAL_PACKAGE_FILES"

  for extra_file in "${extra_files[@]}"; do
    extra_path="package-output/$extra_file"

    test -f "$extra_path"
    test -f "${extra_path}.sig"

    extra_name="$(
      bsdtar -xOf "$extra_path" .PKGINFO |
        sed -n 's/^pkgname = //p'
    )"

    if [[ ! "$extra_name" =~ ^[a-z][a-z0-9-]*$ ||
          -n "${selected_names[$extra_name]+present}" ]]; then
      echo "Invalid or duplicate candidate identity: $extra_name" >&2
      exit 1
    fi

    verify_signed_file "${extra_path}.sig" "$extra_path"

    selected_names["$extra_name"]=1
    candidate_files+=("$extra_file")
    candidate_names+=("$extra_name")
  done
fi


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

  verify_signed_file "$existing_sig" "$existing_pkg"
done

# Reject ambiguous repository state before removing any package.
declare -A package_owners=()

for existing_pkg in "${existing_packages[@]}"; do
  existing_name="$(
    bsdtar -xOf "$existing_pkg" .PKGINFO |
      sed -n "s/^pkgname = //p"
  )"

  if [[ ! "$existing_name" =~ ^[a-z][a-z0-9-]*$ ]]; then
    echo "Invalid package identity: $existing_pkg" >&2
    exit 1
  fi

  if [[ -n "${package_owners[$existing_name]+present}" ]]; then
    echo "Duplicate package identity: $existing_name" >&2
    exit 1
  fi

  package_owners["$existing_name"]="$existing_pkg"
done

# Enforce complete package-family updates.
# Required companions must always be present in the candidate.
# Optional companions must be replaced if already published.
# Reject incomplete updates before displacement or archive staging.
required_companions=()
optional_companions=()

case "$PACKAGE_NAME" in
  ghostty)
    required_companions=(
      ghostty-shell-integration
      ghostty-terminfo
      ghostty-nautilus
    )
    optional_companions=(ghostty-debug)
    ;;
  keepassxc)
    optional_companions=(keepassxc-debug)
    ;;
  syncthing)
    required_companions=(
      syncthing-discosrv
      syncthing-relaysrv
    )
    optional_companions=(
      syncthing-debug
      syncthing-discosrv-debug
      syncthing-relaysrv-debug
    )
    ;;
  wezterm)
    required_companions=(wezterm-debug)
    ;;
esac

for companion in "${required_companions[@]}"; do
  if [[ -z "${selected_names[$companion]+present}" ]]; then
    echo "Incomplete package family $PACKAGE_NAME: missing required companion $companion" >&2
    exit 1
  fi
done

for companion in "${optional_companions[@]}"; do
  if [[ -n "${package_owners[$companion]+present}" &&
        -z "${selected_names[$companion]+present}" ]]; then
    echo "Incomplete package family $PACKAGE_NAME: missing existing optional companion $companion" >&2
    exit 1
  fi
done

# A serialized publisher must not reintroduce an already-published
# package filename. Reject both complete and partial existing pairs.
# This check runs after verification of existing repository signatures
# and before any package displacement or archive staging.
for new_file in "${candidate_files[@]}"; do
  if [[ -e "repo-output/$new_file" ||
        -e "repo-output/${new_file}.sig" ]]; then
    echo "Candidate package version already present: $new_file" >&2
    exit 1
  fi
done

# Track the displaced package independently of archive staging.
displaced_name=""
declare -A displaced_by_name=()

# Remove only versions of the selected package.
for existing_pkg in "${existing_packages[@]}"; do
  existing_name="$(
    bsdtar -xOf "$existing_pkg" .PKGINFO |
      sed -n "s/^pkgname = //p"
  )"

  if [[ -n "${selected_names[$existing_name]+present}" ]]; then
    displaced_by_name["$existing_name"]="${existing_pkg##*/}"

    if [[ "$existing_name" == "$PACKAGE_NAME" ]]; then
      displaced_name="${existing_pkg##*/}"
    fi

    mkdir -p archive-output
    cp -- "$existing_pkg" "${existing_pkg}.sig" archive-output/
    rm -f -- "$existing_pkg" "${existing_pkg}.sig"
  fi
done

for new_file in "${candidate_files[@]}"; do
  cp "package-output/$new_file" repo-output/
  cp "package-output/${new_file}.sig" repo-output/
done

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

  verify_signed_file "${file}.sig" "$file"
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

# Written only after successful repository assembly.
if (( ${#candidate_files[@]} == 1 )); then
  printf '%s\n' "$PACKAGE_NAME" "$PACKAGE_FILE" "$displaced_name" \
    > ../archive-state.txt
else
  {
    printf '%s\n' 'batch-v2'

    for i in "${!candidate_files[@]}"; do
      name="${candidate_names[i]}"

      printf '%s\n' \
        "$name" \
        "${candidate_files[i]}" \
        "${displaced_by_name[$name]:-}"
    done
  } > ../archive-state.txt
fi
