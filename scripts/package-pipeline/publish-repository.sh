#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${PACKAGE_FILE:?PACKAGE_FILE is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_REPO:?GH_REPO is required}"

if [[ ! "$PACKAGE_FILE" =~ ^[a-zA-Z0-9._+-]+[.]pkg[.]tar[.]zst$ ]]; then
  echo "Invalid PACKAGE_FILE: $PACKAGE_FILE" >&2
  exit 1
fi

required_assets=(
  "repo-output/${PACKAGE_FILE}"
  "repo-output/${PACKAGE_FILE}.sig"
  repo-output/t4t3z0r-package-signing.asc
  repo-output/SHA256SUMS
  repo-output/t4t3z0r.files
  repo-output/t4t3z0r.files.sig
  repo-output/t4t3z0r.db
  repo-output/t4t3z0r.db.sig
)

for asset in "${required_assets[@]}"; do
  if [[ ! -f "$asset" ]]; then
    echo "Missing publication asset: $asset" >&2
    exit 1
  fi
done

# Verify assembled asset integrity before GitHub access.
if ! (cd repo-output && sha256sum --check --strict --status SHA256SUMS); then
  echo "Repository asset checksum verification failed" >&2
  exit 1
fi

if ! diff -u \
  <(find repo-output -maxdepth 1 -type f ! -name SHA256SUMS -printf "%f\n" | LC_ALL=C sort) \
  <(sed -n "s/^[[:xdigit:]]\{64\}  //p" repo-output/SHA256SUMS | LC_ALL=C sort)
then
  echo "Checksum manifest does not match assembled assets" >&2
  exit 1
fi

gh release view "$RELEASE_TAG" >/dev/null

# Package first. Existing clients remain on the old valid database
# until the new repository metadata is successfully published.
gh release upload "$RELEASE_TAG" \
  "repo-output/${PACKAGE_FILE}" \
  "repo-output/${PACKAGE_FILE}.sig" \
  --clobber

gh release upload "$RELEASE_TAG" \
  repo-output/t4t3z0r-package-signing.asc \
  repo-output/SHA256SUMS \
  repo-output/t4t3z0r.files \
  repo-output/t4t3z0r.files.sig \
  --clobber

# Database last.
gh release upload "$RELEASE_TAG" \
  repo-output/t4t3z0r.db \
  repo-output/t4t3z0r.db.sig \
  --clobber

mapfile -t desired < <(
  find repo-output \
    -maxdepth 1 \
    -type f \
    -printf '%f\n' \
    | sort
)

# Capture the command status before considering asset deletion.
existing_output="$(
  gh release view "$RELEASE_TAG" \
    --json assets \
    --jq '.assets[].name'
)"

existing=()
if [[ -n "$existing_output" ]]; then
  mapfile -t existing <<< "$existing_output"
fi

for asset in "${existing[@]}"; do
  if ! printf '%s\n' "${desired[@]}" \
    | grep -Fxq -- "$asset"
  then
    gh release delete-asset \
      "$RELEASE_TAG" \
      "$asset" \
      --yes
  fi
done
