#!/usr/bin/env bash
# Build only the agent against the reviewed owned SDK, without changing checkouts.
set -euo pipefail
umask 077
if (( $# > 1 )); then echo 'Usage: build-owned-agent.sh [new-output-directory]' >&2; exit 2; fi
repo=$(cd "$(dirname "$0")/.." && pwd)
sdk=$(cd "$repo/../go-spiffe" && pwd)
plugins=$(cd "$repo/../spire-plugin-sdk" && pwd)
sdk_pin=8ce1b3061da276b934ad86ec69f72c1fd13b3c23
plugins_pin=29a57d508e75c79c4afacc0b50044c79338ce623
for path in "$repo" "$sdk" "$plugins"; do
  if [[ -n $(git -C "$path" status --porcelain) ]]; then
    echo "Refusing an uncommitted source tree: $path" >&2; exit 1
  fi
done
[[ $(git -C "$sdk" rev-parse HEAD) == "$sdk_pin" ]] || { echo 'Owned SDK revision requires explicit review' >&2; exit 1; }
[[ $(git -C "$plugins" rev-parse HEAD) == "$plugins_pin" ]] || { echo 'Plugin SDK revision requires explicit review' >&2; exit 1; }
revision=$(git -C "$repo" rev-parse HEAD)
out=${1:-"$repo/.build/owned-agent/$revision"}
mkdir -p "$(dirname "$out")"
mkdir "$out" # Never overwrite an existing artifact or its provenance.
out=$(cd "$out" && pwd)
mkdir -p "$out/source/spire" "$out/source/go-spiffe" "$out/source/spire-plugin-sdk" "$out/bin"
git -C "$repo" archive "$revision" | tar -x -C "$out/source/spire"
git -C "$sdk" archive "$sdk_pin" | tar -x -C "$out/source/go-spiffe"
git -C "$plugins" archive "$plugins_pin" | tar -x -C "$out/source/spire-plugin-sdk"
printf 'go 1.27.3\n\nuse (\n ./spire\n ./go-spiffe\n ./spire-plugin-sdk\n)\n' > "$out/source/go.work"
export GOTOOLCHAIN=go1.27.3 GOWORK="$out/source/go.work" CGO_ENABLED=0
(
  cd "$out/source/spire"
  go build -trimpath -ldflags="-s -w -X github.com/spiffe/spire/pkg/common/version.githash=$revision" -o "$out/bin/spire-agent" ./cmd/spire-agent
) > "$out/build.log" 2>&1
go version -m "$out/bin/spire-agent" > "$out/go-build-info.txt"
python3 - "$out" "$revision" "$sdk_pin" "$plugins_pin" <<'PY'
import hashlib,json,pathlib,subprocess,sys
r=pathlib.Path(sys.argv[1])
with (r/'bin/spire-agent').open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
manifest={'sourceCommits':dict(zip(['spire','go-spiffe','spire-plugin-sdk'],sys.argv[2:])),'goVersion':subprocess.check_output(['go','version'],text=True).strip(),'binarySHA256':digest,'sourceMode':'committed Git archives','workspace':'source/go.work','productionChanged':False,'agentStarted':False}
(r/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
PY
printf 'Agent artifact: %s/bin/spire-agent\n' "$out"
