#!/usr/bin/env bash
set -euo pipefail

readonly terraform_version=1.10.5
repo_root=$(git rev-parse --show-toplevel)
sandbox=$(mktemp -d "${TMPDIR:-/tmp}/envelope-terraform.XXXXXX")
# shellcheck disable=SC2317 # Invoked indirectly by the EXIT trap.
cleanup() {
  rm -rf "$sandbox"
}
trap cleanup EXIT

install -d \
  "$sandbox/source/example/terraform" \
  "$sandbox/source/testdata/deployment" \
  "$sandbox/source/deploy/terraform/envelope-controller" \
  "$sandbox/source/deploy/terraform/router-attestor" \
  "$sandbox/source/deploy/terraform/controller-acceptance" \
  "$sandbox/source/deploy/systemd" \
  "$sandbox/source/scripts"
cp "$repo_root"/example/terraform/*.tf "$sandbox/source/example/terraform/"
cp "$repo_root/example/terraform/.terraform.lock.hcl" "$sandbox/source/example/terraform/"
cp -R \
  "$repo_root/example/terraform/cloud-init" \
  "$repo_root/example/terraform/modules" \
  "$repo_root/example/terraform/tests" \
  "$sandbox/source/example/terraform/"
cp "$repo_root/testdata/deployment/artifact-fixture" "$sandbox/source/testdata/deployment/"
cp "$repo_root"/deploy/terraform/envelope-controller/*.tf "$sandbox/source/deploy/terraform/envelope-controller/"
cp "$repo_root/deploy/terraform/envelope-controller/.terraform.lock.hcl" "$sandbox/source/deploy/terraform/envelope-controller/"
cp -R \
  "$repo_root/deploy/terraform/envelope-controller/cloud-init" \
  "$repo_root/deploy/terraform/envelope-controller/tests" \
  "$sandbox/source/deploy/terraform/envelope-controller/"
cp "$repo_root/deploy/systemd/envelope-controller.service" "$sandbox/source/deploy/systemd/"
cp "$repo_root/deploy/systemd/envelope-router-attestor.service" "$sandbox/source/deploy/systemd/"
cp "$repo_root"/deploy/terraform/router-attestor/*.tf "$sandbox/source/deploy/terraform/router-attestor/"
cp "$repo_root/deploy/terraform/router-attestor/.terraform.lock.hcl" "$sandbox/source/deploy/terraform/router-attestor/"
cp -R "$repo_root/deploy/terraform/router-attestor/tests" "$sandbox/source/deploy/terraform/router-attestor/"
cp "$repo_root"/deploy/terraform/controller-acceptance/*.tf "$sandbox/source/deploy/terraform/controller-acceptance/"
cp "$repo_root/deploy/terraform/controller-acceptance/.terraform.lock.hcl" "$sandbox/source/deploy/terraform/controller-acceptance/"
cp -R "$repo_root/deploy/terraform/controller-acceptance/tests" "$sandbox/source/deploy/terraform/controller-acceptance/"
cp "$repo_root/scripts/reviewed-go-toolchain.txt" "$sandbox/source/scripts/"

terraform_bin=${TERRAFORM_BIN:-}
if [[ -n "$terraform_bin" && "$terraform_bin" != */* ]]; then
  requested_terraform_bin=$terraform_bin
  if ! terraform_bin=$(command -v "$requested_terraform_bin"); then
    printf 'Terraform command not found in PATH: %s\n' "$requested_terraform_bin" >&2
    exit 1
  fi
elif [[ -z "$terraform_bin" ]] && command -v terraform >/dev/null 2>&1; then
  candidate=$(command -v terraform)
  candidate_version=$("$candidate" version)
  if grep -Fxq "Terraform v$terraform_version" <<<"$candidate_version"; then
    terraform_bin=$candidate
  fi
fi

if [[ -z "$terraform_bin" ]]; then
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) platform=darwin_arm64; expected=51910553dae21dab7f5f55912129602fd902e68a6b6d84b326a556a3e140b98b ;;
    Darwin:x86_64) platform=darwin_amd64; expected=4164db242076c7e99ac6aec67bc42b366925b97267e3883edaca4e4e408b082e ;;
    Linux:aarch64|Linux:arm64) platform=linux_arm64; expected=0ca5d6977c7c46bfa4bbe030030b911e897cf0cb72bff5525fb76c10f1c3409a ;;
    Linux:x86_64|Linux:amd64) platform=linux_amd64; expected=0566a24f5332098b15716ebc394be503f4094acba5ba529bf5eb0698ed5e2a90 ;;
    *) printf '%s\n' 'unsupported platform for pinned Terraform verifier' >&2; exit 1 ;;
  esac
  archive="$sandbox/terraform.zip"
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --output "$archive" "https://releases.hashicorp.com/terraform/$terraform_version/terraform_${terraform_version}_${platform}.zip"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
  else
    actual=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
  fi
  if [[ "$actual" != "$expected" ]]; then
    printf '%s\n' 'pinned Terraform archive checksum mismatch' >&2
    exit 1
  fi
  unzip -q "$archive" -d "$sandbox/terraform-bin"
  terraform_bin="$sandbox/terraform-bin/terraform"
fi

terraform_bin_dir=$(dirname "$terraform_bin")
terraform_bin="$(cd "$terraform_bin_dir" && pwd)/$(basename "$terraform_bin")"
selected_version=$("$terraform_bin" version)
if ! grep -Fxq "Terraform v$terraform_version" <<<"$selected_version"; then
  printf 'expected Terraform %s at %s\n' "$terraform_version" "$terraform_bin" >&2
  exit 1
fi

export TF_IN_AUTOMATION=1
export TF_PLUGIN_CACHE_DIR="$sandbox/terraform-plugin-cache"
install -d "$TF_PLUGIN_CACHE_DIR"

run_terraform_checks() {
  local name=$1
  local terraform_dir=$2
  export TF_DATA_DIR="$sandbox/terraform-data/$name"
  "$terraform_bin" -chdir="$terraform_dir" fmt -check -recursive
  "$terraform_bin" -chdir="$terraform_dir" init -backend=false -lockfile=readonly
  "$terraform_bin" -chdir="$terraform_dir" validate
  "$terraform_bin" -chdir="$terraform_dir" test
}

run_terraform_checks appliance "$sandbox/source/example/terraform"
run_terraform_checks controller "$sandbox/source/deploy/terraform/envelope-controller"
run_terraform_checks router-attestor "$sandbox/source/deploy/terraform/router-attestor"
run_terraform_checks controller-acceptance "$sandbox/source/deploy/terraform/controller-acceptance"
