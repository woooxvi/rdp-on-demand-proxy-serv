#!/usr/bin/env python3
"""
Download or update MaxMind GeoLite2 databases.

Usage:
  With explicit credentials:
    python scripts/update_geoip.py --account-id 123456 --license-key YOUR_KEY

  Read credentials from config.yml (geoip.update.account_id / geoip.update.license_key):
    python scripts/update_geoip.py --config config.yml

  Custom output paths:
    python scripts/update_geoip.py --account-id 123456 --license-key YOUR_KEY \\
        --city-db /data/GeoLite2-City.mmdb --asn-db /data/GeoLite2-ASN.mmdb

MaxMind GeoLite2 is free. Sign up at https://www.maxmind.com/en/geolite2/signup
"""
from __future__ import annotations

import argparse
import base64
import logging
import os
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("geoip_update")

_EDITIONS = ["GeoLite2-City", "GeoLite2-ASN"]
_DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"


def download_edition(edition: str, account_id: str, license_key: str, output_path: Path) -> None:
    url = _DOWNLOAD_URL.format(edition=edition)
    cred = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {cred}",
            "User-Agent": "GeoIP-Update/6.0.0 (linux; x86_64)",
        },
    )
    logger.info(f"Downloading {edition} ...")

    fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
    try:
        os.close(fd)
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(tmp_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(tmp_path) as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb"):
                    file_obj = tar.extractfile(member)
                    if file_obj is not None:
                        output_path.write_bytes(file_obj.read())
                        logger.info(f"  -> {output_path} ({output_path.stat().st_size:,} bytes)")
                        return
            raise RuntimeError(f"No .mmdb file found in archive for {edition}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download/update MaxMind GeoLite2 databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--account-id", help="MaxMind Account ID")
    parser.add_argument("--license-key", help="MaxMind License Key")
    parser.add_argument(
        "--config",
        help="Path to config.yml — reads account_id/license_key from geoip.update section",
    )
    parser.add_argument(
        "--city-db",
        default="./data/GeoLite2-City.mmdb",
        help="Output path for City database (default: ./data/GeoLite2-City.mmdb)",
    )
    parser.add_argument(
        "--asn-db",
        default="./data/GeoLite2-ASN.mmdb",
        help="Output path for ASN database (default: ./data/GeoLite2-ASN.mmdb)",
    )
    args = parser.parse_args()

    account_id: str = args.account_id or ""
    license_key: str = args.license_key or ""

    if (not account_id or not license_key) and args.config:
        try:
            repo_root = Path(__file__).resolve().parent.parent
            sys.path.insert(0, str(repo_root))
            from rdp_proxy.config import load_config  # type: ignore[import]

            cfg = load_config(args.config)
            account_id = account_id or cfg.notifications.geoip.update_account_id
            license_key = license_key or cfg.notifications.geoip.update_license_key
        except Exception as exc:
            logger.error(f"Failed to read config: {exc}")
            sys.exit(1)

    if not account_id or not license_key:
        logger.error(
            "Credentials required. Provide --account-id and --license-key, "
            "or --config with geoip.update.account_id / geoip.update.license_key."
        )
        sys.exit(1)

    targets = {
        "GeoLite2-City": Path(args.city_db),
        "GeoLite2-ASN": Path(args.asn_db),
    }

    errors = 0
    for edition, output_path in targets.items():
        try:
            download_edition(edition, account_id, license_key, output_path)
        except Exception as exc:
            logger.error(f"Failed to download {edition}: {exc}")
            errors += 1

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
