#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${PACKAGE_FILE:?PACKAGE_FILE is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_REPO:?GH_REPO is required}"
: "${PACKAGE_NAME:?PACKAGE_NAME is required}"

if [[ ! "$PACKAGE_FILE" =~ ^[a-zA-Z0-9._+-]+[.]pkg[.]tar[.]zst$ ]]; then
  echo "Invalid PACKAGE_FILE: $PACKAGE_FILE" >&2
  exit 1
fi

candidate_files=("$PACKAGE_FILE")

if [[ -n "${ADDITIONAL_PACKAGE_FILES:-}" ]]; then
  if [[ ! "$ADDITIONAL_PACKAGE_FILES" =~ ^[A-Za-z0-9._+-]+[.]pkg[.]tar[.]zst([ ]+[A-Za-z0-9._+-]+[.]pkg[.]tar[.]zst)*$ ]]; then
    echo "Invalid ADDITIONAL_PACKAGE_FILES" >&2
    exit 1
  fi

  read -r -a extra_files <<< "$ADDITIONAL_PACKAGE_FILES"
  candidate_files+=("${extra_files[@]}")
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

for extra_file in "${candidate_files[@]:1}"; do
  required_assets+=(
    "repo-output/$extra_file"
    "repo-output/${extra_file}.sig"
  )
done

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

# Validate assembly displacement state before GitHub access.
if [[ ! -f archive-state.txt ]]; then
  echo "Missing assembly state" >&2
  exit 1
fi

mapfile -t assembly_state < archive-state.txt

if (( ${#candidate_files[@]} == 1 )); then
  if (( ${#assembly_state[@]} != 3 )); then
    echo "Invalid assembly state" >&2
    exit 1
  fi

  if [[ "${assembly_state[0]}" != "$PACKAGE_NAME" ||
        "${assembly_state[1]}" != "$PACKAGE_FILE" ]]; then
    echo "Assembly identity mismatch" >&2
    exit 1
  fi

  displaced="${assembly_state[2]}"

  if [[ -n "$displaced" ]]; then
    if [[ ! "$displaced" =~ ^[a-zA-Z0-9._+-]+[.]pkg[.]tar[.]zst$ ||
          "$displaced" == "$PACKAGE_FILE" ]]; then
      echo "Invalid displaced package filename" >&2
      exit 1
    fi

    if [[ ! -f "archive-output/$displaced" ||
          ! -f "archive-output/$displaced.sig" ]]; then
      echo "Missing displaced package or signature" >&2
      exit 1
    fi

    shopt -s nullglob
    staged_files=( archive-output/* )
    if (( ${#staged_files[@]} != 2 )); then
      echo "Unexpected archive staging contents" >&2
      exit 1
    fi
  else
    if [[ -d archive-output ]] &&
       [[ -n "$(find archive-output -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      echo "Unexpected archive staging without displacement" >&2
      exit 1
    fi
  fi

  # Verified archival must precede live repository access.
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

  if ! archive_result="$(
    python3 "$script_dir/publication-archive-gate.py" \
      --package "$PACKAGE_NAME" \
      --candidate "$PACKAGE_FILE"
  )"; then
    echo "Archive authorization failed" >&2
    exit 1
  fi

  if ! printf "%s\\n" "$archive_result" | python3 -c   'import json,sys; sys.exit(0 if json.load(sys.stdin).get("gate_passed") is True else 1)'
  then
    echo "Archive gate did not confirm authorization" >&2
    exit 1
  fi

else
  expected_count=$((1 + 3 * ${#candidate_files[@]}))

  if [[ "${assembly_state[0]:-}" != "batch-v2" ||
        "${#assembly_state[@]}" -ne "$expected_count" ]]; then
    echo "Invalid batch assembly state" >&2
    exit 1
  fi

  declare -A seen_names=()
  expected_archive=()

  for i in "${!candidate_files[@]}"; do
    offset=$((1 + 3 * i))
    name="${assembly_state[offset]}"
    file="${assembly_state[offset + 1]}"
    previous="${assembly_state[offset + 2]}"

    if [[ ! "$name" =~ ^[a-z][a-z0-9-]*$ ||
          -n "${seen_names[$name]+present}" ||
          "$file" != "${candidate_files[i]}" ]]; then
      echo "Batch assembly identity mismatch" >&2
      exit 1
    fi

    if (( i == 0 )) && [[ "$name" != "$PACKAGE_NAME" ]]; then
      echo "Primary package identity mismatch" >&2
      exit 1
    fi

    seen_names["$name"]=1

    actual_name="$(
      bsdtar -xOf "repo-output/$file" .PKGINFO |
        sed -n 's/^pkgname = //p'
    )"

    if [[ "$actual_name" != "$name" ]]; then
      echo "Batch package metadata mismatch" >&2
      exit 1
    fi

    if [[ -n "$previous" ]]; then
      if [[ ! "$previous" =~ ^[A-Za-z0-9._+-]+[.]pkg[.]tar[.]zst$ ||
            "$previous" == "$file" ]]; then
        echo "Invalid displaced batch package" >&2
        exit 1
      fi

      if [[ ! -f "archive-output/$previous" ||
            ! -f "archive-output/$previous.sig" ]]; then
        echo "Missing displaced batch package or signature" >&2
        exit 1
      fi

      expected_archive+=("$previous" "$previous.sig")
    fi
  done

  # Reject unexpected, missing, or surplus staged archive files.
  if [[ -d archive-output ]]; then
    mapfile -t actual_archive < <(
      find archive-output -mindepth 1 -maxdepth 1 \
        -printf '%f\n' | LC_ALL=C sort
    )
  else
    actual_archive=()
  fi

  if (( ${#expected_archive[@]} > 0 )); then
    mapfile -t ordered_expected < <(
      printf '%s\n' "${expected_archive[@]}" | LC_ALL=C sort
    )
  else
    ordered_expected=()
  fi

  if [[ "${actual_archive[*]}" != "${ordered_expected[*]}" ]]; then
    echo "Unexpected batch archive staging contents" >&2
    exit 1
  fi

  # Apply the existing per-package archival gate to every identity.
  # No live release upload occurs until every gate succeeds.
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  archive_tmp="$(mktemp -d)"
  trap 'rm -rf -- "$archive_tmp"' EXIT
  mkdir -p "$archive_tmp/staging"

  for i in "${!candidate_files[@]}"; do
    offset=$((1 + 3 * i))
    name="${assembly_state[offset]}"
    file="${assembly_state[offset + 1]}"
    previous="${assembly_state[offset + 2]}"

    rm -f -- "$archive_tmp/staging/"*

    if [[ -n "$previous" ]]; then
      cp -- \
        "archive-output/$previous" \
        "archive-output/$previous.sig" \
        "$archive_tmp/staging/"
    fi

    printf '%s\n' "$name" "$file" "$previous" \
      > "$archive_tmp/state"

    if ! archive_result="$(
      python3 "$script_dir/publication-archive-gate.py" \
        --package "$name" \
        --candidate "$file" \
        --state "$archive_tmp/state" \
        --staging "$archive_tmp/staging"
    )"; then
      echo "Archive authorization failed: $name" >&2
      exit 1
    fi

    if ! printf '%s\n' "$archive_result" |
      python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("gate_passed") is True else 1)'
    then
      echo "Archive gate denied publication: $name" >&2
      exit 1
    fi
  done
fi

gh release view "$RELEASE_TAG" >/dev/null

# Package first. Existing clients remain on the old valid database
# until the new repository metadata is successfully published.
upload_assets=()

for file in "${candidate_files[@]}"; do
  upload_assets+=(
    "repo-output/$file"
    "repo-output/${file}.sig"
  )
done

gh release upload "$RELEASE_TAG" \
  "${upload_assets[@]}" \
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

# Validate the complete remote inventory before deleting anything.
declare -A remote_assets=()
declare -A desired_assets=()

for asset in "${desired[@]}"; do
  desired_assets["$asset"]=1
done

if (( ${#existing[@]} == 0 )); then
  echo "Remote release inventory is empty" >&2
  exit 1
fi

for asset in "${existing[@]}"; do
  if [[ -z "$asset" || "$asset" == */* || "$asset" == "." || "$asset" == ".." ]]; then
    echo "Invalid release asset name: $asset" >&2
    exit 1
  fi

  if [[ -n "${remote_assets[$asset]+present}" ]]; then
    echo "Duplicate remote asset: $asset" >&2
    exit 1
  fi

  remote_assets["$asset"]=1
done

for asset in "${desired[@]}"; do
  if [[ -z "${remote_assets[$asset]+present}" ]]; then
    echo "Expected release asset missing: $asset" >&2
    exit 1
  fi
done

# Refuse unexpected metadata or unrelated files.
for asset in "${existing[@]}"; do
  if [[ -n "${desired_assets[$asset]+present}" ]]; then
    continue
  fi

  case "$asset" in
    *.pkg.tar.zst|*.pkg.tar.zst.sig) ;;
    *)
      echo "Unexpected non-package release asset: $asset" >&2
      exit 1
      ;;
  esac
done

for asset in "${existing[@]}"; do
  if [[ -z "${desired_assets[$asset]+present}" ]]; then
    gh release delete-asset \
      "$RELEASE_TAG" \
      "$asset" \
      --yes
  fi
done
