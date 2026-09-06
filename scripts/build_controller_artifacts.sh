#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'usage: build_controller_artifacts.sh [--output-dir DIR] [--version VERSION] [--architectures amd64,arm64] [--allow-dirty]'
}

output_dir=dist
artifact_version=
architectures=amd64,arm64
allow_dirty=false
while (($#)); do
  case "$1" in
    --output-dir)
      output_dir=${2:?missing output directory}
      shift 2
      ;;
    --version)
      artifact_version=${2:?missing version}
      shift 2
      ;;
    --architectures)
      architectures=${2:?missing architecture list}
      shift 2
      ;;
    --allow-dirty)
      allow_dirty=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

repo_root=$(git rev-parse --show-toplevel)
revision=$(git -C "$repo_root" rev-parse --verify HEAD)
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct HEAD)
source_dirty=false
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=normal)" ]]; then
  source_dirty=true
fi
if [[ "$source_dirty" == true && "$allow_dirty" != true ]]; then
  printf '%s\n' 'refusing a release artifact from a dirty worktree; use --allow-dirty only for non-live fixture tests' >&2
  exit 1
fi
build_date=$(date -u -r "$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d "@$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ')
go_version=$(go env GOVERSION)
reviewed_go_version=$(tr -d '[:space:]' <"$repo_root/scripts/reviewed-go-toolchain.txt")
if [[ "$go_version" != "$reviewed_go_version" ]]; then
  printf 'reviewed Go toolchain is %s, found %s\n' "$reviewed_go_version" "$go_version" >&2
  exit 1
fi
if [[ -z "$artifact_version" ]]; then
  artifact_version="0.0.0+$(git -C "$repo_root" rev-parse --short=12 HEAD)"
fi
if [[ ! "$artifact_version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]]; then
  printf '%s\n' 'artifact version contains unsupported characters or is too long' >&2
  exit 2
fi

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
tmp_dir=$(mktemp -d "$output_dir/.controller-build.XXXXXX")
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

IFS=',' read -ra requested_arches <<<"$architectures"
if ((${#requested_arches[@]} == 0)); then
  printf '%s\n' 'architecture list must not be empty' >&2
  exit 2
fi
seen_arches=,
for arch in "${requested_arches[@]}"; do
  case "$arch" in
    amd64|arm64) ;;
    *)
      printf 'unsupported architecture: %s\n' "$arch" >&2
      exit 2
      ;;
  esac
  if [[ "$seen_arches" == *",$arch,"* ]]; then
    printf 'duplicate architecture: %s\n' "$arch" >&2
    exit 2
  fi
  seen_arches+="$arch,"
done

manifest_entries=()
build_artifact() {
  local component=$1 package=$2 artifact=$3 arch=$4 ec2_arch=$5 digest size
  SOURCE_DATE_EPOCH="$source_date_epoch" \
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -mod=readonly -trimpath -buildvcs=true \
      -ldflags "-buildid= -s -w -X main.version=$artifact_version -X main.revision=$revision -X main.buildDate=$build_date -X main.sourceModified=$source_dirty" \
      -o "$tmp_dir/$artifact" "$package"
  chmod 0755 "$tmp_dir/$artifact"
  python3 "$repo_root/scripts/inspect_artifact.py" "$tmp_dir/$artifact" \
    --expect-architecture "$arch" \
    --expect-revision "$revision" \
    --expect-modified "$source_dirty" \
    --expect-go-version "$go_version" \
    --expect-version "$artifact_version"
  digest=$(sha256_file "$tmp_dir/$artifact")
  size=$(wc -c <"$tmp_dir/$artifact" | tr -d ' ')
  manifest_entries+=("{\"component\":\"$component\",\"architecture\":\"$arch\",\"ec2_architecture\":\"$ec2_arch\",\"file\":\"$artifact\",\"goos\":\"linux\",\"goarch\":\"$arch\",\"go_version\":\"$go_version\",\"vcs_revision\":\"$revision\",\"vcs_modified\":$source_dirty,\"version\":\"$artifact_version\",\"sha256\":\"$digest\",\"size\":$size}")
  mv -f "$tmp_dir/$artifact" "$output_dir/$artifact"
}

for arch in "${requested_arches[@]}"; do
  case "$arch" in
    amd64) ec2_arch=x86_64 ;;
    arm64) ec2_arch=arm64 ;;
  esac
  build_artifact \
    envelope-controller \
    "$repo_root/cmd/envelope-controller" \
    "envelope-controller-linux-$arch" \
    "$arch" \
    "$ec2_arch"
  build_artifact \
    envelope-controller-topology \
    "$repo_root/deploy/terraform/envelope-controller/tools/topology-identity" \
    "envelope-controller-topology-linux-$arch" \
    "$arch" \
    "$ec2_arch"
  build_artifact \
    envelope-controller-deploy \
    "$repo_root/cmd/envelope-controller-deploy" \
    "envelope-controller-deploy-linux-$arch" \
    "$arch" \
    "$ec2_arch"
  build_artifact \
    envelope-router-attestor \
    "$repo_root/cmd/envelope-router-attestor" \
    "envelope-router-attestor-linux-$arch" \
    "$arch" \
    "$ec2_arch"
done

manifest_tmp="$tmp_dir/controller-manifest.json"
{
  printf '{"schema":1,"component":"envelope-controller","version":"%s","revision":"%s","source_dirty":%s,"source_date_epoch":%s,"build_date":"%s","go_version":"%s","artifacts":[' \
    "$artifact_version" "$revision" "$source_dirty" "$source_date_epoch" "$build_date" "$go_version"
  separator=
  for entry in "${manifest_entries[@]}"; do
    printf '%s%s' "$separator" "$entry"
    separator=,
  done
  printf ']}'
} >"$manifest_tmp"
mv -f "$manifest_tmp" "$output_dir/controller-manifest.json"
printf 'built %d controller artifact(s); manifest=%s\n' "${#manifest_entries[@]}" "$output_dir/controller-manifest.json"
