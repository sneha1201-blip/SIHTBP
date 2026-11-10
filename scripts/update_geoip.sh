#!/usr/bin/env bash
# ==============================================================================
# AICTE Cyber Security Cell | Smart India Hackathon 2026 (SIH ID: 26106)
# MaxMind GeoLite2-City and GeoLite2-ASN Database Updater
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET_DIR="${PROJECT_ROOT}/backend/storage/geoip"

if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "ERROR: MAXMIND_LICENSE_KEY environment variable is not set." >&2
    echo "Usage: MAXMIND_LICENSE_KEY=your_key_here ./scripts/update_geoip.sh" >&2
    exit 1
fi

mkdir -p "${TARGET_DIR}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo "======================================================================"
echo "Updating MaxMind GeoLite2 Databases for Forensic Intelligence..."
echo "Target Directory: ${TARGET_DIR}"
echo "======================================================================"

# 1. Download & Extract GeoLite2-City
echo "[1/2] Downloading GeoLite2-City..."
CITY_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
curl -sSfL "${CITY_URL}" -o "${TEMP_DIR}/GeoLite2-City.tar.gz"
tar -xzf "${TEMP_DIR}/GeoLite2-City.tar.gz" -C "${TEMP_DIR}"
find "${TEMP_DIR}" -name "GeoLite2-City.mmdb" -exec cp {} "${TARGET_DIR}/GeoLite2-City.mmdb" \;

# 2. Download & Extract GeoLite2-ASN
echo "[2/2] Downloading GeoLite2-ASN..."
ASN_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
curl -sSfL "${ASN_URL}" -o "${TEMP_DIR}/GeoLite2-ASN.tar.gz"
tar -xzf "${TEMP_DIR}/GeoLite2-ASN.tar.gz" -C "${TEMP_DIR}"
find "${TEMP_DIR}" -name "GeoLite2-ASN.mmdb" -exec cp {} "${TARGET_DIR}/GeoLite2-ASN.mmdb" \;

echo "----------------------------------------------------------------------"
echo "Successfully updated MaxMind GeoIP databases:"
ls -lh "${TARGET_DIR}/GeoLite2-City.mmdb" "${TARGET_DIR}/GeoLite2-ASN.mmdb"
echo "======================================================================"

