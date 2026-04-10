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
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("geoip_update")

_EDITIONS = ["GeoLite2-City", "GeoLite2-ASN"]
_DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
_LEGACY_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={license_key}&suffix=tar.gz"

_MIRROR_URLS = {
    "GeoLite2-City": (
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb",
    ),
    "GeoLite2-ASN": (
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb",
    ),
}


def _extract_mmdb_from_targz(targz_path: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(targz_path) as tar:
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                file_obj = tar.extractfile(member)
                if file_obj is not None:
                    output_path.write_bytes(file_obj.read())
                    logger.info(f"  -> {output_path} ({output_path.stat().st_size:,} bytes)")
                    return
        raise RuntimeError("No .mmdb file found in downloaded archive")


def _download_targz_and_extract(url: str, headers: dict[str, str], output_path: Path) -> None:
    req = urllib.request.Request(url, headers=headers)
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
        _extract_mmdb_from_targz(tmp_path, output_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _download_raw_mmdb(url: str, output_path: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(req, timeout=120) as resp:
        output_path.write_bytes(resp.read())
    if output_path.stat().st_size < 1024 * 1024:
        raise RuntimeError(f"Downloaded file too small: {output_path.stat().st_size} bytes")
    logger.info(f"  -> {output_path} ({output_path.stat().st_size:,} bytes)")


def download_edition(edition: str, account_id: str, license_key: str, output_path: Path) -> None:
    logger.info(f"Downloading {edition} ...")
    errors: list[str] = []

    try:
        url = _DOWNLOAD_URL.format(edition=edition)
        cred = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
        _download_targz_and_extract(
            url,
            headers={
                "Authorization": f"Basic {cred}",
                "User-Agent": "GeoIP-Update/6.0.0 (linux; x86_64)",
            },
            output_path=output_path,
        )
        return
    except Exception as exc:
        errors.append(f"MaxMind auth API failed: {exc}")

    try:
        legacy_url = _LEGACY_DOWNLOAD_URL.format(edition=edition, license_key=license_key)
        _download_targz_and_extract(
            legacy_url,
            headers={"User-Agent": "GeoIP-Update/6.0.0 (linux; x86_64)"},
            output_path=output_path,
        )
        return
    except Exception as exc:
        errors.append(f"MaxMind legacy API failed: {exc}")

    for mirror_url in _MIRROR_URLS.get(edition, ()): 
        try:
            _download_raw_mmdb(mirror_url, output_path)
            logger.warning(f"Downloaded {edition} from mirror fallback")
            return
        except Exception as exc:
            errors.append(f"Mirror failed ({mirror_url}): {exc}")

    raise RuntimeError("; ".join(errors))


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
    success = 0
    for edition, output_path in targets.items():
        try:
            download_edition(edition, account_id, license_key, output_path)
            success += 1
        except Exception as exc:
            logger.error(f"Failed to download {edition}: {exc}")
            errors += 1

    if success == 0:
        logger.error("No GeoIP database downloaded successfully")
        sys.exit(1)

    if errors:
        logger.warning("Downloaded partially: some databases failed, but at least one is available")
    sys.exit(0)


if __name__ == "__main__":
    main()
