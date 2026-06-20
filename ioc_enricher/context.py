import csv
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ioc_enricher.ioc.types import IocType


class InternalContext:
    """Local business context used to tune scoring and tag indicators."""

    def __init__(
        self,
        allowlist=None,
        blocklist=None,
        business_domains=None,
        cidrs=None,
        assets=None,
    ):
        self.allowlist = {v.lower() for v in (allowlist or [])}
        self.blocklist = {v.lower() for v in (blocklist or [])}
        self.business_domains = {
            v.lower().lstrip(".") for v in (business_domains or [])
        }
        self.cidrs = [ipaddress.ip_network(c, strict=False) for c in (cidrs or [])]
        self.assets = assets or {}

    @classmethod
    def empty(cls):
        return cls()

    @classmethod
    def from_files(cls, paths=None, asset_inventory=None):
        data: dict[str, list[Any]] = {
            "allowlist": [],
            "blocklist": [],
            "business_domains": [],
            "cidrs": [],
        }
        for path in paths or []:
            payload = json.loads(Path(path).read_text())
            for key in data:
                data[key].extend(payload.get(key, []))

        return cls(
            allowlist=data["allowlist"],
            blocklist=data["blocklist"],
            business_domains=data["business_domains"],
            cidrs=data["cidrs"],
            assets=load_asset_inventory(asset_inventory) if asset_inventory else {},
        )

    def evaluate(self, ioc, ioc_type):
        tags = []
        reasons = []
        key = ioc.lower()
        host = _host_for(ioc, ioc_type).lower()

        if key in self.allowlist or host in self.allowlist:
            tags.append("allowlisted_asset")
            reasons.append("allowlisted_asset")
        if key in self.blocklist or host in self.blocklist:
            tags.append("local_blocklist")
            reasons.append("local_blocklist")

        if ioc_type in (IocType.IPV4, IocType.IPV6):
            try:
                ip = ipaddress.ip_address(ioc)
            except ValueError:
                ip = None
            if ip:
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    tags.append("internal_asset")
                    reasons.append("private_ip")
                if any(ip in net for net in self.cidrs):
                    tags.append("internal_asset")
                    reasons.append("corp_cidr")

        if host and self._is_business_domain(host):
            tags.append("corp_domain")
            reasons.append("allowlisted_asset")

        asset = self.assets.get(key) or self.assets.get(host)
        if asset:
            tags.extend(asset.get("tags", []))
            if "scanner_ip" in asset.get("tags", []):
                reasons.append("known_scanner")
            if "known_vendor" in asset.get("tags", []):
                reasons.append("allowlisted_asset")
            if "vpn_endpoint" in asset.get("tags", []):
                reasons.append("allowlisted_asset")

        return {
            "tags": sorted(set(tags)),
            "reasons": sorted(set(reasons)),
            "asset": asset or None,
        }

    def _is_business_domain(self, host):
        return any(
            host == domain or host.endswith("." + domain)
            for domain in self.business_domains
        )


def _host_for(ioc, ioc_type):
    if ioc_type == IocType.URL:
        return urlparse(ioc).hostname or ""
    if ioc_type in (IocType.DOMAIN, IocType.EMAIL):
        return ioc.rsplit("@", 1)[-1]
    return ioc


def load_asset_inventory(path):
    assets = {}
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            value = (
                row.get("ioc")
                or row.get("ip")
                or row.get("host")
                or row.get("domain")
                or row.get("asset")
                or ""
            ).strip()
            if not value:
                continue
            tags: list[str] = []
            for field in ("tags", "tag"):
                if row.get(field):
                    tags.extend(
                        t.strip() for t in row[field].replace(";", ",").split(",")
                    )
            for flag in (
                "internal_asset",
                "known_vendor",
                "vpn_endpoint",
                "scanner_ip",
            ):
                if row.get(flag, "").strip().lower() in ("1", "true", "yes", "y"):
                    tags.append(flag)
            assets[value.lower()] = {
                "name": row.get("name") or row.get("hostname") or "",
                "owner": row.get("owner") or "",
                "tags": sorted({t for t in tags if t}),
            }
    return assets
