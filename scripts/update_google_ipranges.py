#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import urllib.error
import urllib.request

SOURCES = {
    "common-crawlers": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "special-crawlers": "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "user-triggered-fetchers-google": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    "user-triggered-agents": "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json",
}

OUTPUT = Path("dist/google-ipranges.json")
USER_AGENT = (
    "DCK-Google-IPRanges-Relay/1.0 "
    "(+https://github.com/digicompkala/dck-google-ipranges-relay)"
)
MAX_BODY = 5 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_source(name: str, url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status = getattr(response, "status", response.getcode())
            if status != 200:
                raise RuntimeError(f"{name}: HTTP {status}")
            body = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{name}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{name}: network error: {exc.reason}") from exc

    if not body or len(body) > MAX_BODY:
        raise RuntimeError(f"{name}: invalid body size {len(body)}")

    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"{name}: invalid JSON") from exc

    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        raise RuntimeError(f"{name}: prefixes missing or empty")

    networks = []
    for row in prefixes:
        if not isinstance(row, dict):
            continue
        for field in ("ipv4Prefix", "ipv6Prefix"):
            value = row.get(field)
            if not value:
                continue
            try:
                net = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError as exc:
                raise RuntimeError(f"{name}: invalid CIDR {value!r}") from exc
            networks.append(str(net))

    networks = sorted(
        set(networks),
        key=lambda cidr: (
            ipaddress.ip_network(cidr).version,
            int(ipaddress.ip_network(cidr).network_address),
            ipaddress.ip_network(cidr).prefixlen,
        ),
    )

    if not networks:
        raise RuntimeError(f"{name}: no valid CIDRs")

    return {
        "url": url,
        "creation_time": str(data.get("creationTime", ""))[:100],
        "raw_sha256": hashlib.sha256(body).hexdigest(),
        "range_count": len(networks),
        "ranges": networks,
    }


def semantic_payload() -> dict:
    sources = {}
    flat = []

    for name, url in SOURCES.items():
        meta = fetch_source(name, url)
        sources[name] = meta
        flat.extend({"source": name, "cidr": cidr} for cidr in meta["ranges"])
        print(
            f"SOURCE={name} RANGES={meta['range_count']} "
            f"CREATION={meta['creation_time']}"
        )

    if not flat:
        raise RuntimeError("aggregate range list is empty")

    unique_cidrs = sorted(
        {row["cidr"] for row in flat},
        key=lambda cidr: (
            ipaddress.ip_network(cidr).version,
            int(ipaddress.ip_network(cidr).network_address),
            ipaddress.ip_network(cidr).prefixlen,
        ),
    )

    if len(unique_cidrs) < 10:
        raise RuntimeError(
            f"aggregate CIDR count unexpectedly low: {len(unique_cidrs)}"
        )

    return {
        "schema_version": 1,
        "policy": {
            "included_sources": list(SOURCES.keys()),
            "excluded_source": "user-triggered-fetchers.json",
            "excluded_reason": (
                "This broader feed may include user-controlled Google Cloud/App Engine fetchers; "
                "it is intentionally not trusted as a blanket whitelist source."
            ),
        },
        "sources": sources,
        "ranges": flat,
        "counts": {
            "source_entries": len(flat),
            "unique_cidrs": len(unique_cidrs),
            "ipv4_unique": sum(1 for c in unique_cidrs if ipaddress.ip_network(c).version == 4),
            "ipv6_unique": sum(1 for c in unique_cidrs if ipaddress.ip_network(c).version == 6),
        },
    }


def canonical_json(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def main() -> int:
    payload = semantic_payload()
    payload_hash = hashlib.sha256(canonical_json(payload)).hexdigest()

    old = None
    if OUTPUT.exists():
        try:
            old = json.loads(OUTPUT.read_text(encoding="utf-8"))
        except Exception:
            old = None

    if isinstance(old, dict) and old.get("payload_sha256") == payload_hash:
        print(f"STATUS=NO_CHANGE PAYLOAD_SHA256={payload_hash}")
        return 0

    document = {
        **payload,
        "generated_at": utc_now(),
        "payload_sha256": payload_hash,
        "relay": {
            "repository": "digicompkala/dck-google-ipranges-relay",
            "generator": "scripts/update_google_ipranges.py",
        },
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(OUTPUT)

    print(
        "STATUS=UPDATED "
        f"UNIQUE_CIDRS={document['counts']['unique_cidrs']} "
        f"PAYLOAD_SHA256={payload_hash}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
