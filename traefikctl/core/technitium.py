"""Thin client for the Technitium DNS HTTP API, plus zone-aware
classification of names traefikctl wants to publish.

Read-only except for delete_record(), which is the single permitted write
operation (guided conflict resolution) and enforces a hard denylist.
API shapes verified empirically against Technitium on 10.10.30.30
(2026-08-06): GET /api/zones/records/{get,delete}, token as query param,
{"status": "ok", "response": {...}} envelopes, disabled records included
in reads, per-type value parameters on delete.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum

import httpx

from ..config import Settings

log = logging.getLogger("traefikctl.technitium")

# httpx logs full request URLs at INFO — that would put the API token into
# container logs. Keep it quiet.
logging.getLogger("httpx").setLevel(logging.WARNING)

API_TIMEOUT = 3.0  # hard rule: never hang a request path on Technitium

# Value parameter each record type needs on delete. Types not listed here
# cannot be deleted through traefikctl — handle those in the Technitium UI.
_DELETE_VALUE_PARAM = {
    "A": "ipAddress",
    "AAAA": "ipAddress",
    "CNAME": "cname",
    "TXT": "text",
    "PTR": "ptrName",
}

# Record types that are never deletable regardless of name.
_PROTECTED_TYPES = {"SOA", "NS"}


class TechnitiumError(Exception):
    """API reachable but the call failed (bad token, permission, ...)."""


@dataclass
class ZoneRecord:
    name: str
    type: str
    ttl: int
    disabled: bool
    rdata: dict

    @property
    def value(self) -> str:
        """Human-readable record value for display and delete params."""
        for key in ("ipAddress", "cname", "text", "nameServer", "ptrName"):
            if key in self.rdata:
                return str(self.rdata[key])
        return str(self.rdata)

    @property
    def label(self) -> str:
        state = "DISABLED" if self.disabled else "enabled"
        return f"{self.name} {self.type} → {self.value} (ttl {self.ttl}, {state})"


class ZoneKind(Enum):
    DISABLED_INTEGRATION = "disabled-integration"  # no token configured
    UNAVAILABLE = "unavailable"  # API down/unreachable — degrade gracefully
    NO_RECORD = "no-record"  # wildcard will carry the name (wildcard mode)
    MISSING_RECORD = "missing-record"  # explicit mode: record required, absent
    INGRESS_ALIAS = "ingress-alias"  # explicit record already → ingress
    CONFLICT = "conflict"  # enabled record points elsewhere
    DISABLED_CONFLICT = "disabled-conflict"  # the k2pve case


@dataclass
class ZoneVerdict:
    kind: ZoneKind
    records: list[ZoneRecord] = field(default_factory=list)  # the conflicts
    detail: str = ""

    @property
    def blocks(self) -> bool:
        return self.kind in (
            ZoneKind.CONFLICT,
            ZoneKind.DISABLED_CONFLICT,
            ZoneKind.MISSING_RECORD,
        )


class TechnitiumClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.technitium_token)

    def _call(self, endpoint: str, **params) -> dict:
        """One API call. Raises httpx errors for unreachable/timeout and
        TechnitiumError for API-level failures."""
        params["token"] = self.settings.technitium_token
        r = httpx.get(
            f"{self.settings.technitium_url}/api/{endpoint}",
            params=params,
            timeout=API_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "ok":
            raise TechnitiumError(
                data.get("errorMessage") or f"status={data.get('status')}"
            )
        return data.get("response", {})

    def get_records(self, fqdn: str) -> list[ZoneRecord]:
        """Records (including disabled ones) at exactly this name."""
        resp = self._call(
            "zones/records/get",
            domain=fqdn,
            zone=self.settings.technitium_zone,
        )
        return [
            ZoneRecord(
                name=r.get("name", ""),
                type=r.get("type", ""),
                ttl=int(r.get("ttl", 0)),
                disabled=bool(r.get("disabled", False)),
                rdata=r.get("rData", {}) or {},
            )
            for r in resp.get("records", [])
            if r.get("name", "").lower() == fqdn.lower()
        ]

    def get_zone(self) -> list[ZoneRecord]:
        """Every record in the zone (for the DNS panel and the SOA)."""
        resp = self._call(
            "zones/records/get",
            domain=self.settings.technitium_zone,
            zone=self.settings.technitium_zone,
            listZone="true",
        )
        return [
            ZoneRecord(
                name=r.get("name", ""),
                type=r.get("type", ""),
                ttl=int(r.get("ttl", 0)),
                disabled=bool(r.get("disabled", False)),
                rdata=r.get("rData", {}) or {},
            )
            for r in resp.get("records", [])
        ]

    def get_wildcard_target(self) -> str | None:
        """IP the zone wildcard points at, or None if absent/disabled/unknown.
        Used in explicit mode to tell 'points at the other ingress' apart
        from 'points at a device' in conflict messaging."""
        try:
            for r in self.get_records(f"*.{self.settings.technitium_zone}"):
                if r.type == "A" and not r.disabled:
                    return r.rdata.get("ipAddress")
        except (httpx.HTTPError, TechnitiumError, ValueError):
            return None
        return None

    def get_negative_ttl(self) -> int | None:
        """The zone's negative-caching TTL (SOA minimum), for honest
        'stale NXDOMAIN' messaging after a delete."""
        try:
            for r in self.get_zone():
                if r.type == "SOA":
                    return int(r.rdata.get("minimum", 0)) or None
        except (httpx.HTTPError, TechnitiumError, ValueError):
            return None
        return None

    def denylist_reason(self, record: ZoneRecord) -> str | None:
        """Why this record must never be deleted, or None if allowed."""
        zone = self.settings.technitium_zone.lower()
        name = record.name.lower().rstrip(".")
        if record.type.upper() in _PROTECTED_TYPES:
            return f"{record.type} records are protected"
        if name == f"*.{zone}":
            return "the wildcard record is the backbone of ingress routing"
        if name == zone:
            return "the zone apex is protected"
        if name == f"dns1.{zone}":
            return "dns1 is the DNS server itself"
        if record.type.upper() not in _DELETE_VALUE_PARAM:
            return (
                f"{record.type} records can't be deleted through traefikctl — "
                "use the Technitium console"
            )
        return None

    def delete_record(self, record: ZoneRecord) -> None:
        """THE single write operation. Denylist is enforced here as the
        last line of defense — callers must have checked it already."""
        reason = self.denylist_reason(record)
        if reason:
            raise TechnitiumError(f"refusing to delete {record.label}: {reason}")
        value_param = _DELETE_VALUE_PARAM[record.type.upper()]
        self._call(
            "zones/records/delete",
            domain=record.name,
            zone=self.settings.technitium_zone,
            type=record.type,
            **{value_param: record.value},
        )
        log.info("DELETED Technitium record: %s", record.label)


def classify(fqdn: str, settings: Settings) -> ZoneVerdict:
    """Zone-aware verdict for publishing fqdn. Never raises: API failure
    degrades to UNAVAILABLE so Technitium being down can't block publishing."""
    client = TechnitiumClient(settings)
    if not client.enabled:
        return ZoneVerdict(ZoneKind.DISABLED_INTEGRATION)
    try:
        records = client.get_records(fqdn)
    except (httpx.HTTPError, TechnitiumError, ValueError) as e:
        log.warning("zone introspection unavailable: %s", e)
        return ZoneVerdict(ZoneKind.UNAVAILABLE, detail=str(e))

    disabled = [r for r in records if r.disabled]
    enabled_elsewhere = [
        r
        for r in records
        if not r.disabled
        and not (r.type == "A" and r.rdata.get("ipAddress") == settings.ingress_ip)
    ]
    ingress_alias = [
        r
        for r in records
        if not r.disabled
        and r.type == "A"
        and r.rdata.get("ipAddress") == settings.ingress_ip
    ]

    if settings.wildcard_covers_ingress:
        return _classify_wildcard_mode(disabled, enabled_elsewhere, ingress_alias)
    return _classify_explicit_mode(
        fqdn, client, settings, disabled, enabled_elsewhere, ingress_alias
    )


def _classify_wildcard_mode(
    disabled: list[ZoneRecord],
    enabled_elsewhere: list[ZoneRecord],
    ingress_alias: list[ZoneRecord],
) -> ZoneVerdict:
    """ingress01 reality: the wildcard points at this ingress, so no record
    means covered, and any specific record is an override."""
    if disabled:
        return ZoneVerdict(
            ZoneKind.DISABLED_CONFLICT,
            records=disabled + enabled_elsewhere,
            detail=(
                "A disabled record still occupies the name in the zone: the "
                "wildcard is never consulted and lookups return NXDOMAIN. "
                "Delete the record to let the wildcard take over."
            ),
        )
    if enabled_elsewhere:
        return ZoneVerdict(
            ZoneKind.CONFLICT,
            records=enabled_elsewhere,
            detail=(
                "An enabled record overrides the wildcard, so traffic will "
                "bypass Traefik. Delete it to publish through the ingress."
            ),
        )
    if ingress_alias:
        return ZoneVerdict(
            ZoneKind.INGRESS_ALIAS,
            detail="Explicit A record already points at the ingress — "
            "harmless duplicate of the wildcard.",
        )
    return ZoneVerdict(
        ZoneKind.NO_RECORD,
        detail="No specific record — the wildcard covers this name.",
    )


def _classify_explicit_mode(
    fqdn: str,
    client: TechnitiumClient,
    settings: Settings,
    disabled: list[ZoneRecord],
    enabled_elsewhere: list[ZoneRecord],
    ingress_alias: list[ZoneRecord],
) -> ZoneVerdict:
    """ingress02 reality: the wildcard points at the OTHER ingress, so a
    specific A record -> this ingress IP is REQUIRED, and its absence means
    the published route would be unreachable."""
    if disabled:
        return ZoneVerdict(
            ZoneKind.DISABLED_CONFLICT,
            records=disabled + enabled_elsewhere,
            detail=(
                "A disabled record still occupies the name in the zone and "
                "lookups return NXDOMAIN. Delete it, then create an enabled "
                f"A record {fqdn} → {settings.ingress_ip} in Technitium."
            ),
        )
    if enabled_elsewhere:
        wildcard_target = client.get_wildcard_target()
        conflict_ips = {
            r.rdata.get("ipAddress") for r in enabled_elsewhere if r.type == "A"
        }
        if wildcard_target and conflict_ips == {wildcard_target}:
            detail = (
                f"The record points at the other ingress ({wildcard_target}) — "
                "likely a wildcard duplicate or a wrong-ingress publish. This "
                f"ingress needs {fqdn} → {settings.ingress_ip}: delete the "
                "record, then create the correct one in Technitium."
            )
        else:
            detail = (
                "The record points at a device, so traffic bypasses this "
                f"ingress. To publish here it must be {fqdn} → "
                f"{settings.ingress_ip}: delete the record, then create the "
                "correct one in Technitium."
            )
        return ZoneVerdict(
            ZoneKind.CONFLICT, records=enabled_elsewhere, detail=detail
        )
    if ingress_alias:
        return ZoneVerdict(
            ZoneKind.INGRESS_ALIAS,
            detail="Explicit A record points at this ingress — the required "
            "state on this ingress.",
        )
    return ZoneVerdict(
        ZoneKind.MISSING_RECORD,
        detail=(
            "No record exists, and on this ingress the wildcard does NOT "
            "cover published names — the route would be unreachable. Create "
            f"an A record {fqdn} → {settings.ingress_ip} in Technitium first "
            "(traefikctl never creates records)."
        ),
    )
