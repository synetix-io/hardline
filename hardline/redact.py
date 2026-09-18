"""Strip secrets before anything leaves the process — logs, AI prompts, reports.

Rule of thumb: if it would let someone log in, it is redacted. Interface names,
IP addresses and rule structure stay, because remediation has to name them.
The browser runs the same rules before upload (static/app.js); this is the
second wall.
"""
from __future__ import annotations

import re

SECRET_KEYS = (
    "password", "secret", "private-key", "pre-shared-key", "wpa2-pre-shared-key",
    "wpa-pre-shared-key", "passphrase", "key", "psk", "community", "shared-secret",
    "radius-secret", "token", "api-key", "cloud-key", "user-pass", "wps-pin",
    "encryption-password", "auth-key", "master-key", "private-key-name",
)

_KV = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in SECRET_KEYS) + r")=(\"(?:[^\"\\]|\\.)*\"|\S+)",
    re.I,
)
_SSH_KEY = re.compile(r"(ssh-(?:rsa|ed25519|dss|ecdsa)[^\s\"]*)\s+[A-Za-z0-9+/=]{20,}")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# SNMP community strings are written as `name=` on lines that carry access flags.
# The defaults stay visible because the rules look for them; anything else is a credential.
_COMMUNITY_LINE = re.compile(r"\b(read-access|write-access|security|authentication-protocol)=")
_NAME = re.compile(r"\bname=(\"(?:[^\"\\]|\\.)*\"|\S+)")


def _mask_community(m: re.Match) -> str:
    bare = m.group(1).strip('"').lower()
    return m.group(0) if bare in ("public", "private", "<redacted>") else "name=<redacted>"


def redact(text: str) -> str:
    text = _KV.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = "\n".join(_NAME.sub(_mask_community, l) if _COMMUNITY_LINE.search(l) else l
                     for l in text.split("\n"))
    text = _SSH_KEY.sub(r"\1 <redacted>", text)
    text = _B64_BLOB.sub("<redacted>", text)
    return text


def redact_lines(lines: list[str]) -> list[str]:
    return [redact(l) for l in lines]
