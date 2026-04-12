#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-config/subscribe.json}"
CACHE_DIR="${2:-cache}"

mkdir -p "$CACHE_DIR"

now=$(date +%s)
failed=0

for name in $(jq -r 'keys[]' "$CONFIG"); do
    url_env=$(jq -r ".\"$name\".url_env" "$CONFIG")
    output=$(jq -r ".\"$name\".output" "$CONFIG")
    interval=$(jq -r ".\"$name\".interval" "$CONFIG")
    client=$(jq -r ".\"$name\".client // \"\"" "$CONFIG")

    url="${!url_env:-}"
    if [[ -z "$url" ]]; then
        echo "::warning::$name: env \$$url_env is not set, skipping"
        continue
    fi

    cache_file="$CACHE_DIR/$name.json"
    cache_info="$CACHE_DIR/$name.json.info"
    cache_ts="$CACHE_DIR/$name.timestamp"

    # Check if cache is still fresh
    if [[ -f "$cache_ts" && -f "$cache_file" ]]; then
        last=$(cat "$cache_ts")
        age=$((now - last))
        if ((age < interval)); then
            echo "$name: cache is fresh (age=${age}s, interval=${interval}s), skipping download"
            cp "$cache_file" "$output"
            [[ -f "$cache_info" ]] && cp "$cache_info" "$output.info"
            continue
        fi
    fi

    # Try to download
    echo "$name: downloading..."
    if ./subscribe.sh "$url" "$output" ${client:+"$client"}; then
        echo "$name: download succeeded, updating cache"
        cp "$output" "$cache_file"
        [[ -f "$output.info" ]] && cp "$output.info" "$cache_info"
        echo "$now" > "$cache_ts"
    else
        echo "::warning::$name: download failed"
        if [[ -f "$cache_file" ]]; then
            echo "$name: using cached version"
            cp "$cache_file" "$output"
            [[ -f "$cache_info" ]] && cp "$cache_info" "$output.info"
        else
            echo "::error::$name: no cache available"
            failed=1
        fi
    fi
done

exit $failed
