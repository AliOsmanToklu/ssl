"""Regenerate src/kalkan/scanner/data/software.json.

Release cycles come from the endoflife.date API; OpenSSH (not covered there) is
read from the official release notes and IIS is maintained by hand because its
lifecycle follows the Windows Server release it ships with.

Usage: python scripts/update_software_db.py
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OUTPUT = (
    Path(__file__).resolve().parents[1] / "src" / "kalkan" / "scanner" / "data" / "software.json"
)
USER_AGENT = "kalkan-software-db-updater (+https://github.com/AliOsmanToklu/ssl)"

# our key -> (endoflife.date product id, display name)
ENDOFLIFE_PRODUCTS: dict[str, tuple[str, str]] = {
    "php": ("php", "PHP"),
    "nginx": ("nginx", "nginx"),
    "apache": ("apache-http-server", "Apache HTTP Server"),
    "tomcat": ("tomcat", "Apache Tomcat"),
    "openssl": ("openssl", "OpenSSL"),
    "wordpress": ("wordpress", "WordPress"),
    "drupal": ("drupal", "Drupal"),
    "joomla": ("joomla", "Joomla"),
    "mysql": ("mysql", "MySQL"),
    "mariadb": ("mariadb", "MariaDB"),
    "proftpd": ("proftpd", "ProFTPD"),
    "exim": ("exim", "Exim"),
    # client-side libraries, fingerprinted from <script> URLs
    "jquery": ("jquery", "jQuery"),
    "bootstrap": ("bootstrap", "Bootstrap"),
    "angularjs": ("angularjs", "AngularJS"),
    "vue": ("vue", "Vue.js"),
}

# Supported release lines that still have well-known, widely exploited bugs below a
# given patch release: (minimum safe version, reason shown to users in Turkish).
MINIMUM_SAFE: dict[str, tuple[str, str]] = {
    "jquery": ("3.5.0", "CVE-2020-11022 / CVE-2020-11023 (XSS) açıkları"),
}

# IIS versions map 1:1 to Windows Server releases; EOL = end of extended support.
IIS_CYCLES: list[dict[str, Any]] = [
    {"cycle": "10.0", "eol": False, "latest": None},
    {"cycle": "8.5", "eol": "2023-10-10", "latest": "8.5"},
    {"cycle": "8.0", "eol": "2023-10-10", "latest": "8.0"},
    {"cycle": "7.5", "eol": "2020-01-14", "latest": "7.5"},
    {"cycle": "7.0", "eol": "2020-01-14", "latest": "7.0"},
    {"cycle": "6.0", "eol": "2015-07-14", "latest": "6.0"},
]

# regreSSHion (CVE-2024-6387) affects 8.5p1-9.7p1; everything older has other
# well-known issues. 9.8 is the first release considered safe here.
OPENSSH_MINIMUM_SAFE = "9.8"


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        body: bytes = response.read()
    return body.decode("utf-8")


def endoflife_cycles(product: str) -> list[dict[str, Any]]:
    raw = json.loads(fetch(f"https://endoflife.date/api/{product}.json"))
    return [
        {"cycle": str(item["cycle"]), "eol": item.get("eol", False), "latest": item.get("latest")}
        for item in raw
    ]


def openssh_latest() -> str:
    notes = fetch("https://www.openssh.com/releasenotes.html")
    versions: list[str] = re.findall(r"OpenSSH (\d+\.\d+) was released on \d{4}-\d{2}-\d{2}", notes)
    if not versions:
        raise RuntimeError("could not find any OpenSSH release in the release notes")
    return max(versions, key=lambda v: tuple(int(p) for p in v.split(".")))


def build() -> dict[str, Any]:
    products: dict[str, Any] = {}
    for key, (eol_id, name) in ENDOFLIFE_PRODUCTS.items():
        products[key] = {"name": name, "cycles": endoflife_cycles(eol_id)}
        if key in MINIMUM_SAFE:
            products[key]["minimum_safe"], products[key]["minimum_safe_reason"] = MINIMUM_SAFE[key]
        print(f"  {name}: {len(products[key]['cycles'])} cycles", file=sys.stderr)
    latest_ssh = openssh_latest()
    products["openssh"] = {
        "name": "OpenSSH",
        # Only the newest OpenSSH release is maintained upstream.
        "cycles": [{"cycle": "", "eol": False, "latest": latest_ssh}],
        "minimum_safe": OPENSSH_MINIMUM_SAFE,
        "minimum_safe_reason": "CVE-2024-6387 (regreSSHion) ve daha eski bilinen açıklar",
    }
    print(f"  OpenSSH: latest {latest_ssh}", file=sys.stderr)
    products["iis"] = {"name": "Microsoft IIS", "cycles": IIS_CYCLES}
    return {
        "generated_at": datetime.now(UTC).date().isoformat(),
        "sources": ["https://endoflife.date", "https://www.openssh.com/releasenotes.html"],
        "products": dict(sorted(products.items())),
    }


def main() -> int:
    print("Fetching release data...", file=sys.stderr)
    data = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
