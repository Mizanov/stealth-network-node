#!/usr/bin/env bash
# ==============================================================================
# Ruleset Downloader & Validator for Sing-Box
# Downloads official SagerNet geoip and geosite binary rulesets (.srs)
# Validates HTTP response codes and verifies binary magic header (SRS\x01)
# Enforces mandatory checks: installation aborts if any mandatory ruleset is missing.
# ==============================================================================

set -euo pipefail

TARGET_DIR="${1:-}"
if [ -z "$TARGET_DIR" ]; then
    echo "ERROR: Target ruleset directory must be specified as first argument." >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Mandatory rulesets required for server sing-box routing core
MANDATORY_SERVER_RULESETS=(
    "geoip-ru.srs:geoip"
    "geosite-category-gov-ru.srs:geosite"
    "geosite-category-ads-all.srs:geosite"
    "geosite-openai.srs:geosite"
    "geosite-anthropic.srs:geosite"
    "geosite-xai.srs:geosite"
)

# Client rulesets served via Nginx for remote client routing
CLIENT_RULESETS=(
    "geosite-blender.srs:geosite"
    "geosite-canonical.srs:geosite"
    "geosite-debian.srs:geosite"
    "geosite-doi.srs:geosite"
    "geosite-drweb.srs:geosite"
    "geosite-duckduckgo.srs:geosite"
    "geosite-duolingo.srs:geosite"
    "geosite-elsevier.srs:geosite"
    "geosite-google.srs:geosite"
    "geosite-mailru.srs:geosite"
    "geosite-oracle.srs:geosite"
    "geosite-ozon.srs:geosite"
    "geosite-pinterest.srs:geosite"
    "geosite-python.srs:geosite"
    "geosite-reddit.srs:geosite"
    "geosite-sci-hub.srs:geosite"
    "geosite-sciencedirect.srs:geosite"
    "geosite-springer.srs:geosite"
    "geosite-telegram.srs:geosite"
    "geosite-tumblr.srs:geosite"
    "geosite-twitch.srs:geosite"
    "geosite-vk.srs:geosite"
    "geosite-yahoo.srs:geosite"
    "geosite-yandex.srs:geosite"
    "geosite-zoom.srs:geosite"
)

validate_srs_format() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return 1
    fi
    # Check file size (at least 16 bytes)
    local fsize
    fsize=$(wc -c < "$file" | tr -d ' ')
    if [ "$fsize" -lt 16 ]; then
        return 1
    fi

    # Sing-Box binary rule-set files start with magic bytes "SRS\x01" (hex: 53525301)
    local magic
    magic=$(head -c 4 "$file" | xxd -p 2>/dev/null || od -N 4 -t x1 "$file" 2>/dev/null | head -n 1 | awk '{$1=""; gsub(/ /,""); print}' || true)
    if [ "$magic" = "53525301" ]; then
        return 0
    fi
    return 1
}

download_ruleset() {
    local filename="$1"
    local rtype="$2"
    local is_mandatory="$3"

    local dest="$TARGET_DIR/$filename"
    local tmp_dest="${dest}.tmp_$$"

    local primary_url="https://raw.githubusercontent.com/SagerNet/sing-${rtype}/rule-set/${filename}"
    local fallback_url="https://fastly.jsdelivr.net/gh/SagerNet/sing-${rtype}@rule-set/${filename}"

    local success=0

    # Try primary URL
    if curl -fsSL --retry 2 --connect-timeout 8 --max-time 30 "$primary_url" -o "$tmp_dest" 2>/dev/null; then
        if validate_srs_format "$tmp_dest"; then
            success=1
        fi
    fi

    # Try fallback URL if primary failed
    if [ "$success" -eq 0 ]; then
        if curl -fsSL --retry 2 --connect-timeout 8 --max-time 30 "$fallback_url" -o "$tmp_dest" 2>/dev/null; then
            if validate_srs_format "$tmp_dest"; then
                success=1
            fi
        fi
    fi

    if [ "$success" -eq 1 ]; then
        mv -f "$tmp_dest" "$dest"
        chmod 644 "$dest"
        echo "[OK] Ruleset $filename downloaded and validated (SRS binary format)."
        return 0
    else
        rm -f "$tmp_dest"
        if [ "$is_mandatory" = "true" ]; then
            echo "[FATAL] Failed to download or validate MANDATORY ruleset '$filename' from upstream sources!" >&2
            return 1
        else
            echo "[WARNING] Optional ruleset '$filename' could not be downloaded." >&2
            return 0
        fi
    fi
}

echo "=== Downloading and Validating Mandatory Server Rulesets ==="
for item in "${MANDATORY_SERVER_RULESETS[@]}"; do
    filename="${item%%:*}"
    rtype="${item##*:}"
    if ! download_ruleset "$filename" "$rtype" "true"; then
        echo "ERROR: Missing mandatory server ruleset '$filename'. Aborting." >&2
        exit 1
    fi
done

# Verify all mandatory files are present and valid
for item in "${MANDATORY_SERVER_RULESETS[@]}"; do
    filename="${item%%:*}"
    if ! validate_srs_format "$TARGET_DIR/$filename"; then
        echo "ERROR: Mandatory ruleset '$TARGET_DIR/$filename' is missing or corrupt! Aborting." >&2
        exit 1
    fi
done

echo "=== Deploying Local Static Rulesets ==="
if [ -f "$SCRIPT_DIR/config/rulesets/torrent-clients.json" ]; then
    cp "$SCRIPT_DIR/config/rulesets/torrent-clients.json" "$TARGET_DIR/torrent-clients.json"
    chmod 644 "$TARGET_DIR/torrent-clients.json"
    echo "[OK] torrent-clients.json deployed."
fi

echo "=== Downloading Client Rulesets for Nginx Serving ==="
for item in "${CLIENT_RULESETS[@]}"; do
    filename="${item%%:*}"
    rtype="${item##*:}"
    download_ruleset "$filename" "$rtype" "false" || true
done

echo "=== All mandatory rulesets successfully verified ==="
exit 0
