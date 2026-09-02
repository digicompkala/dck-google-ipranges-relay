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

DIST = Path("dist")
OUTPUT = DIST / "google-ipranges.json"
USER_AGENT = (
    "DCK-Google-IPRanges-Relay/1.1 "
    "(+https://github.com/digicompkala/dck-google-ipranges-relay)"
)
MAX_BODY = 5 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_json_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def fetch_source(name: str, url: str) -> tuple[dict, dict]:
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

    normalized_prefixes = []
    networks = []

    for row in prefixes:
        if not isinstance(row, dict):
            continue

        normalized_row = {}
        for field in ("ipv4Prefix", "ipv6Prefix"):
            value = row.get(field)
            if not value:
                continue
            try:
                net = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError as exc:
                raise RuntimeError(f"{name}: invalid CIDR {value!r}") from exc

            cidr = str(net)
            normalized_row[field] = cidr
            networks.append(cidr)

        if normalized_row:
            normalized_prefixes.append(normalized_row)

    networks = sorted(
        set(networks),
        key=lambda cidr: (
            ipaddress.ip_network(cidr).version,
            int(ipaddress.ip_network(cidr).network_address),
            ipaddress.ip_network(cidr).prefixlen,
        ),
    )

    if not networks or not normalized_prefixes:
        raise RuntimeError(f"{name}: no valid CIDRs")

    # Preserve Google's expected crawler-feed schema so the WordPress plugin
    # can consume the relay without changing its parser.
    relay_document = {
        "creationTime": str(data.get("creationTime", ""))[:100],
        "prefixes": normalized_prefixes,
    }

    meta = {
        "url": url,
        "creation_time": relay_document["creationTime"],
        "raw_sha256": hashlib.sha256(body).hexdigest(),
        "range_count": len(networks),
        "ranges": networks,
    }

    return meta, relay_document


def canonical_json(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def main() -> int:
    sources = {}
    flat = []
    relay_documents = {}

    for name, url in SOURCES.items():
        meta, relay_document = fetch_source(name, url)
        sources[name] = meta
        relay_documents[name] = relay_document
        flat.extend({"source": name, "cidr": cidr} for cidr in meta["ranges"])
        print(
            f"SOURCE={name} RANGES={meta['range_count']} "
            f"CREATION={meta['creation_time']}"
        )

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

    payload = {
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

    payload_hash = hashlib.sha256(canonical_json(payload)).hexdigest()

    document = {
        **payload,
        "generated_at": utc_now(),
        "payload_sha256": payload_hash,
        "relay": {
            "repository": "digicompkala/dck-google-ipranges-relay",
            "generator": "scripts/update_google_ipranges.py",
        },
    }

    # Always materialize the four source-compatible relay files. Git will only
    # commit them if their content actually changed.
    for name, relay_document in relay_documents.items():
        atomic_json_write(DIST / f"{name}.json", relay_document)

    old = None
    if OUTPUT.exists():
        try:
            old = json.loads(OUTPUT.read_text(encoding="utf-8"))
        except Exception:
            old = None

    if not isinstance(old, dict) or old.get("payload_sha256") != payload_hash:
        atomic_json_write(OUTPUT, document)
        print(
            "STATUS=UPDATED "
            f"UNIQUE_CIDRS={document['counts']['unique_cidrs']} "
            f"PAYLOAD_SHA256={payload_hash}"
        )
    else:
        print(f"STATUS=NO_CHANGE PAYLOAD_SHA256={payload_hash}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
