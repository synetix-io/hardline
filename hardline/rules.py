"""The finding rules. This file is the product.

Each rule reads the parsed export and returns a Finding or None. Rules are
deterministic: they never call a model, and a competent RouterOS engineer
should be able to argue with each one line by line. Every finding names the
line it saw, why it matters, and the exact RouterOS commands that fix it —
using the interface and list names from *this* export, not a generic template.

Severity: critical > high > medium > low > info.
Axis:     exposure  = could someone get in / move / change things?
          evidence  = if they did, would you know and could you prove it?
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .parser import Config, Entry, version_tuple

# Fixed versions from CERT Polska / MikroTik, September 2026 (MikroTrick).
# 6.x long-term 6.49.21 · 7.x long-term 7.23.4 · 7.x stable 7.24.2
PATCHED = {
    "6": (6, 49, 21),
    "7-lt": (7, 23, 4),
    "7": (7, 24, 2),
}
MIKROTRICK_CVES = ["CVE-2026-67276", "CVE-2026-86060", "CVE-2026-67277",
                   "CVE-2026-67278", "CVE-2026-67279", "CVE-2026-67281"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    axis: str
    observed: str
    why: str
    fix: list[str]
    evidence: list[str] = field(default_factory=list)   # raw lines (redacted later)
    refs: list[str] = field(default_factory=list)
    caution: str | None = None                          # lock-out / breakage warning


RULES: list[dict] = []


def rule(rid: str, title: str, severity: str, axis: str):
    def deco(fn: Callable[[Config], tuple | None]):
        RULES.append({"id": rid, "title": title, "severity": severity, "axis": axis, "fn": fn})
        return fn
    return deco


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_patched(version: str | None) -> bool | None:
    """True if at or above the fixed release; None if version unknown."""
    vt = version_tuple(version)
    if not vt:
        return None
    if vt[0] == 6:
        return vt >= PATCHED["6"]
    if vt[0] == 7:
        if len(vt) >= 2 and vt[1] < 24:
            return vt >= PATCHED["7-lt"]
        return vt >= PATCHED["7"]
    return True  # unknown major; do not scare people about versions we do not know


def _input_rules(cfg: Config) -> list[Entry]:
    return [e for e in cfg.section("/ip firewall filter") if e.cmd == "add" and e.get("chain") == "input"
            and not e.flag("disabled")]


def _is_broad(e: Entry) -> bool:
    """A rule with no narrowing matchers except interface scoping."""
    narrow = ("protocol", "dst-port", "src-port", "src-address", "dst-address",
              "connection-state", "src-address-list", "dst-address-list",
              "connection-mark", "packet-mark", "icmp-options", "tcp-flags", "ipsec-policy")
    return not any(k in e.args for k in narrow)


def _has_input_drop(cfg: Config) -> bool:
    return any(e.get("action") in ("drop", "reject") and _is_broad(e) for e in _input_rules(cfg))


def _has_input_accept_all(cfg: Config) -> Entry | None:
    for e in _input_rules(cfg):
        if e.get("action") == "accept" and _is_broad(e) and not e.get("in-interface") \
                and not e.get("in-interface-list"):
            return e
    return None


def _wan_scope(cfg: Config) -> str:
    """Matcher fragment that scopes a firewall rule to the WAN side of this router."""
    if cfg.wan_interface_list():
        return f"in-interface-list={cfg.wan_interface_list()}"
    wans = cfg.wan_interfaces()
    if wans:
        return f"in-interface={wans[0]}"
    return "in-interface-list=WAN"


def _mgmt_nets(cfg: Config) -> str:
    """Best guess at the management subnet for `address=` restrictions."""
    for e in cfg.section("/ip address"):
        a = e.get("address") or ""
        iface = e.get("interface") or ""
        if a and not any(w == iface for w in cfg.wan_interfaces()):
            if a.startswith(("10.", "192.168.", "172.")):
                net = a.split("/")[0].rsplit(".", 1)[0] + ".0/" + (a.split("/")[1] if "/" in a else "24")
                return net
    return "192.168.88.0/24"


def _exposed_note(cfg: Config) -> str:
    return ("" if _has_input_drop(cfg)
            else " There is no catch-all drop on the input chain, so this is reachable from the internet.")


# ── exposure rules ───────────────────────────────────────────────────────────

@rule("HL-001", "MikroTrick: SSH reachable on an unpatched RouterOS", "critical", "exposure")
def r001(cfg: Config):
    patched = _is_patched(cfg.version)
    if patched is not False or not cfg.service_enabled("ssh", default=True):
        return None
    sev = "critical" if not _has_input_drop(cfg) else "high"
    svc = cfg.service("ssh")
    restricted = bool(svc and svc.get("address"))
    if restricted and sev == "critical":
        sev = "high"
    target = "7.24.2 (stable) or 7.23.4 (long-term)" if (version_tuple(cfg.version) or (7,))[0] == 7 else "6.49.21"
    return dict(
        severity=sev,
        observed=f"RouterOS {cfg.version} with the SSH service enabled"
                 + (f", restricted to {svc.get('address')}" if restricted else "")
                 + ". The MikroTrick chain (CVE-2026-67276 + CVE-2026-86060) gives unauthenticated root "
                   "over SSH on this version." + _exposed_note(cfg),
        why="CERT Polska confirmed active exploitation in September 2026. 122,500 routers had SSH "
            "exposed on 5 Sep. An attacker only needs to reach port 22 and know a user exists.",
        fix=[f"/system package update check-for-updates", f"/system package update install",
             f"# upgrade to {target}, then:", "/ip service set ssh address=" + _mgmt_nets(cfg),
             "/ip ssh set strong-crypto=yes"],
        evidence=[svc.raw] if svc else [],
        refs=MIKROTRICK_CVES + ["https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/"],
        caution="Upgrading reboots the router. Restricting SSH by address will lock out any admin "
                "not on that subnet — confirm your own source address first.",
    )


@rule("HL-002", "RouterOS below the September 2026 security release", "high", "exposure")
def r002(cfg: Config):
    if _is_patched(cfg.version) is not False:
        return None
    if cfg.service_enabled("ssh", default=True):
        return None  # HL-001 covers it with the sharper story
    return dict(
        observed=f"RouterOS {cfg.version}. Fixed releases are 6.49.21 / 7.23.4 / 7.24.2.",
        why="Six CVEs were fixed in the September release, not only the SSH chain. MikroTik's "
            "advisory says 'important security update' and nothing else — assume the worst.",
        fix=["/system package update check-for-updates", "/system package update install"],
        refs=MIKROTRICK_CVES,
        caution="Upgrading reboots the router.",
    )


@rule("HL-003", "No catch-all drop on the input chain", "critical", "exposure")
def r003(cfg: Config):
    if _has_input_drop(cfg):
        return None
    scope = _wan_scope(cfg)
    rules = _input_rules(cfg)
    return dict(
        observed="The input chain has no broad drop or reject rule"
                 + (" — in fact it has no input rules at all." if not rules else "."),
        why="Every service on this router — Winbox, SSH, API, web, SNMP — is reachable from "
            "any address that can route to it. This single rule is what separates a private "
            "router from a Shodan result.",
        fix=["/ip firewall filter",
             "add chain=input action=accept connection-state=established,related,untracked comment=\"hardline: keep sessions\"",
             "add chain=input action=drop connection-state=invalid comment=\"hardline: drop invalid\"",
             "add chain=input action=accept protocol=icmp comment=\"hardline: allow ping\"",
             f"add chain=input action=accept in-interface-list=!{cfg.wan_interface_list() or 'WAN'} comment=\"hardline: allow LAN\"",
             f"add chain=input action=drop {scope} comment=\"hardline: drop everything else from WAN\""],
        evidence=[e.raw for e in rules[:5]],
        caution="Add the accept rules BEFORE the drop. If you manage this router over the WAN "
                "interface, add a `src-address=<your IP>` accept rule first or you will lock "
                "yourself out. Use Safe Mode (Ctrl+X in terminal) while applying.",
    )


@rule("HL-004", "Input chain accepts everything", "high", "exposure")
def r004(cfg: Config):
    e = _has_input_accept_all(cfg)
    if not e:
        return None
    return dict(
        observed="An input rule accepts all traffic with no matchers before any drop.",
        why="A catch-all accept makes every rule after it dead code. It is usually left over "
            "from troubleshooting.",
        fix=[f"# remove or narrow the rule on line {e.line}:", f"/ip firewall filter remove [find where comment=\"{e.get('comment', '')}\" chain=input action=accept]"
             if e.get("comment") else f"# /ip firewall filter print; then remove the accept-all rule on line {e.line}"],
        evidence=[e.raw],
    )


@rule("HL-005", "Telnet service enabled", "high", "exposure")
def r005(cfg: Config):
    if not cfg.service_enabled("telnet", default=True):
        return None
    svc = cfg.service("telnet")
    return dict(
        severity="critical" if not _has_input_drop(cfg) else "high",
        observed="Telnet is enabled" + (" (RouterOS default — not mentioned in the export)." if not svc else ".")
                 + _exposed_note(cfg),
        why="Telnet sends the admin password in clear text. There is no reason to have it on in 2026.",
        fix=["/ip service set telnet disabled=yes"],
        evidence=[svc.raw] if svc else [],
    )


@rule("HL-006", "FTP service enabled", "medium", "exposure")
def r006(cfg: Config):
    if not cfg.service_enabled("ftp", default=True):
        return None
    svc = cfg.service("ftp")
    return dict(
        severity="high" if not _has_input_drop(cfg) else "medium",
        observed="FTP is enabled" + (" (RouterOS default)." if not svc else ".") + _exposed_note(cfg),
        why="FTP is clear-text and is the historic path for dropping malicious scripts on RouterOS. "
            "Use SFTP over SSH or Winbox file upload instead.",
        fix=["/ip service set ftp disabled=yes"],
        evidence=[svc.raw] if svc else [],
    )


@rule("HL-007", "Web management over plain HTTP", "medium", "exposure")
def r007(cfg: Config):
    if not cfg.service_enabled("www", default=True):
        return None
    svc = cfg.service("www")
    if svc and svc.get("address"):
        return None
    return dict(
        severity="high" if not _has_input_drop(cfg) else "medium",
        observed="WebFig over HTTP (port 80) is enabled with no address restriction." + _exposed_note(cfg),
        why="Credentials cross the wire unencrypted, and the HTTP server has been the entry point "
            "for several RouterOS exploits (CVE-2018-14847 and later).",
        fix=[f"/ip service set www address={_mgmt_nets(cfg)}", "# or, if you use Winbox anyway:",
             "/ip service set www disabled=yes"],
        evidence=[svc.raw] if svc else [],
    )


@rule("HL-008", "RouterOS API enabled without address restriction", "high", "exposure")
def r008(cfg: Config):
    if not cfg.service_enabled("api", default=True):
        return None
    svc = cfg.service("api")
    if svc and svc.get("address"):
        return None
    return dict(
        observed="The API service (tcp/8728) is enabled and not restricted by address"
                 + (" (RouterOS default)." if not svc else ".") + _exposed_note(cfg),
        why="The API is a full write path with plain-text authentication. Billing systems "
            "(Splynx, UISP, Powercode) need it — from one address, not from everywhere.",
        fix=[f"/ip service set api address={_mgmt_nets(cfg)}",
             "# or disable it and use api-ssl:", "/ip service set api disabled=yes"],
        evidence=[svc.raw] if svc else [],
        caution="If a billing or monitoring system uses the API, add its address to the list "
                "before applying or it will stop provisioning.",
    )


@rule("HL-009", "Winbox not restricted by address", "medium", "exposure")
def r009(cfg: Config):
    if not cfg.service_enabled("winbox", default=True):
        return None
    svc = cfg.service("winbox")
    if svc and svc.get("address"):
        return None
    return dict(
        severity="high" if not _has_input_drop(cfg) else "medium",
        observed="Winbox (tcp/8291) accepts connections from any address." + _exposed_note(cfg),
        why="Winbox is the most brute-forced port on RouterOS. An address list costs nothing.",
        fix=[f"/ip service set winbox address={_mgmt_nets(cfg)}"],
        evidence=[svc.raw] if svc else [],
        caution="Include the address you are connecting from now, or the next Winbox connect fails.",
    )


@rule("HL-010", "SSH strong-crypto not enabled", "low", "exposure")
def r010(cfg: Config):
    if not cfg.service_enabled("ssh", default=True):
        return None
    e = cfg.first("/ip ssh")
    if e and e.flag("strong-crypto"):
        return None
    return dict(
        observed="`/ip ssh strong-crypto` is not set to yes.",
        why="Without it RouterOS negotiates legacy ciphers and MACs that automated scanners "
            "flag and that weaken host-key authentication.",
        fix=["/ip ssh set strong-crypto=yes forwarding-enabled=no"],
        evidence=[e.raw] if e else [],
    )


@rule("HL-011", "Default `admin` account still in use", "medium", "exposure")
def r011(cfg: Config):
    users = [e for e in cfg.section("/user") if e.cmd in ("add", "set")]
    admin = next((e for e in users if (e.get("name") == "admin") or (e.cmd == "set" and e.target == "admin")), None)
    other_full = [e for e in users if e.get("name") not in (None, "admin") and e.get("group") == "full"]
    if admin is None and other_full:
        return None  # admin renamed / removed and a named full user exists — good
    if admin is not None and admin.flag("disabled"):
        return None
    return dict(
        observed="The default `admin` user is present" + (" and no other full-privilege user is defined." if not other_full else "."),
        why="Every password-guessing bot on the internet tries `admin` first. A named account "
            "also gives you attribution — you can tell which person or system did what.",
        fix=["/user add name=<your-name> group=full password=<strong-password>",
             "# log in as the new user, then:", "/user disable admin"],
        evidence=[admin.raw] if admin else [],
        caution="Create and test the new user before disabling admin.",
    )


@rule("HL-012", "Full-privilege user without allowed-address", "low", "exposure")
def r012(cfg: Config):
    hits = [e for e in cfg.section("/user") if e.cmd == "add" and e.get("group") == "full"
            and not e.get("allowed-address") and e.get("name") != "admin"]
    if not hits:
        return None
    names = ", ".join(e.get("name") or "?" for e in hits)
    return dict(
        observed=f"Full-privilege user(s) {names} may log in from any address.",
        why="`allowed-address` is a second wall behind the firewall. Service accounts for "
            "billing and monitoring in particular should be pinned to one source.",
        fix=[f"/user set [find name={(hits[0].get('name'))}] allowed-address={_mgmt_nets(cfg)}"],
        evidence=[e.raw for e in hits[:5]],
    )


@rule("HL-013", "SNMP with default or write-capable community", "high", "exposure")
def r013(cfg: Config):
    snmp = cfg.first("/snmp")
    if snmp and not snmp.flag("enabled"):
        return None
    comms = cfg.section("/snmp community")
    bad = []
    for e in comms:
        name = (e.get("name") or "").lower()
        untouched_default = e.cmd == "set" and "default=yes" in (e.target or "") and not e.get("name")
        if e.flag("write-access") or name in ("public", "private") or untouched_default:
            bad.append(e)
    if snmp and snmp.flag("enabled") and not comms:
        bad = []  # enabled with untouched default community "public"
        return dict(
            observed="SNMP is enabled and the community list was not changed — RouterOS default is `public` read-only.",
            why="`public` is the first thing any scanner tries. It leaks interfaces, addresses, "
                "neighbors and routing to anyone who can reach udp/161.",
            fix=["/snmp community set [find default=yes] name=<random-string> addresses=" + _mgmt_nets(cfg),
                 "# better: SNMPv3", "/snmp community add name=<name> security=private authentication-protocol=SHA1 encryption-protocol=AES authentication-password=<pw> encryption-password=<pw>"],
            evidence=[snmp.raw],
        )
    if not bad:
        return None
    write = any(e.flag("write-access") for e in bad)
    return dict(
        severity="high" if write else "medium",
        observed=("An SNMP community has write access." if write else "A default or unauthenticated SNMP community is configured.")
                 + _exposed_note(cfg),
        why="SNMP write on RouterOS can reboot the device and change interfaces. Even read-only "
            "`public` hands an attacker the network map.",
        fix=["/snmp community set [find name=public] name=<random-string> write-access=no addresses=" + _mgmt_nets(cfg),
             "/snmp community set [find write-access=yes] write-access=no"],
        evidence=[e.raw for e in bad[:5]],
    )


@rule("HL-014", "Open DNS resolver", "high", "exposure")
def r014(cfg: Config):
    dns = cfg.first("/ip dns")
    if not dns or not dns.flag("allow-remote-requests"):
        return None
    if _has_input_drop(cfg):
        # A broad WAN drop covers udp/53 unless an accept for 53 precedes it.
        accepts_53 = any(e.get("action") == "accept" and "53" in (e.get("dst-port") or "") for e in _input_rules(cfg))
        if not accepts_53:
            return None
    return dict(
        observed="`allow-remote-requests=yes` and udp/53 is reachable from the WAN side.",
        why="Open resolvers get abused for DNS amplification within hours of appearing on the "
            "internet, and your upstream will rate-limit or null-route you for it.",
        fix=[f"/ip firewall filter add chain=input action=drop protocol=udp dst-port=53 {_wan_scope(cfg)} comment=\"hardline: no DNS from WAN\" place-before=0",
             f"/ip firewall filter add chain=input action=drop protocol=tcp dst-port=53 {_wan_scope(cfg)} comment=\"hardline: no DNS from WAN\" place-before=0"],
        evidence=[dns.raw],
    )


@rule("HL-015", "UPnP enabled", "medium", "exposure")
def r015(cfg: Config):
    e = cfg.first("/ip upnp")
    if not e or not e.flag("enabled"):
        return None
    return dict(
        observed="UPnP is enabled.",
        why="Any device on the LAN can open inbound ports through the router without asking. "
            "On an ISP or business edge that is never intended.",
        fix=["/ip upnp set enabled=no"],
        evidence=[e.raw],
    )


@rule("HL-016", "Neighbor discovery on all interfaces", "low", "exposure")
def r016(cfg: Config):
    e = cfg.first("/ip neighbor discovery-settings")
    lst = e.get("discover-interface-list") if e else None
    if lst and lst.lower() not in ("all", "dynamic", "none") and not lst.startswith("!"):
        return None
    if lst and lst.lower() == "none":
        return None
    return dict(
        observed="MNDP/CDP/LLDP discovery runs on " + (f"`{lst}`" if lst else "all interfaces (RouterOS default)") + ".",
        why="The router announces its identity, model, version and addresses to whoever is on the "
            "wire — including the WAN. Attackers use it to pick targets by version.",
        fix=[f"/ip neighbor discovery-settings set discover-interface-list=!{cfg.wan_interface_list() or 'WAN'}"],
        evidence=[e.raw] if e else [],
    )


@rule("HL-017", "MAC-server / MAC-Winbox on all interfaces", "medium", "exposure")
def r017(cfg: Config):
    ms = cfg.first("/tool mac-server")
    mw = cfg.first("/tool mac-server mac-winbox")
    bad = []
    for e in (ms, mw):
        lst = e.get("allowed-interface-list") if e else None
        if e is None or lst is None or lst.lower() == "all":
            bad.append(e)
    if not bad:
        return None
    return dict(
        observed="Layer-2 management (MAC-telnet / MAC-Winbox) is allowed on all interfaces"
                 + (" (RouterOS default)." if all(b is None for b in bad) else "."),
        why="Anyone on the same broadcast domain as the WAN port — think a shared switch at a "
            "tower or in a datacentre — can reach management without an IP address.",
        fix=[f"/tool mac-server set allowed-interface-list=!{cfg.wan_interface_list() or 'WAN'}",
             f"/tool mac-server mac-winbox set allowed-interface-list=!{cfg.wan_interface_list() or 'WAN'}"],
        evidence=[e.raw for e in bad if e],
    )


@rule("HL-018", "Bandwidth-test server enabled", "low", "exposure")
def r018(cfg: Config):
    e = cfg.first("/tool bandwidth-server")
    if e and not e.flag("enabled") and "enabled" in e.args:
        return None
    return dict(
        observed="The bandwidth-test server is enabled" + (" (RouterOS default)." if not e else "."),
        why="It lets anyone who can authenticate saturate your uplink on demand. Turn it on when you test, off when you are done.",
        fix=["/tool bandwidth-server set enabled=no"],
        evidence=[e.raw] if e else [],
    )


@rule("HL-019", "SOCKS proxy enabled", "high", "exposure")
def r019(cfg: Config):
    e = cfg.first("/ip socks")
    if not e or not e.flag("enabled"):
        return None
    return dict(
        severity="critical" if not _has_input_drop(cfg) else "high",
        observed="The SOCKS proxy is enabled." + _exposed_note(cfg),
        why="Almost nobody enables SOCKS on purpose. It is the signature of a compromised "
            "RouterOS device being resold as a proxy node. Treat this as a possible incident.",
        fix=["/ip socks set enabled=no", "/ip socks access remove [find]",
             "# then check for scripts and schedulers you did not create:",
             "/system script print", "/system scheduler print"],
        evidence=[e.raw],
    )


@rule("HL-020", "Web proxy enabled", "medium", "exposure")
def r020(cfg: Config):
    e = cfg.first("/ip proxy")
    if not e or not e.flag("enabled"):
        return None
    return dict(
        severity="high" if not _has_input_drop(cfg) else "medium",
        observed="The HTTP web proxy is enabled." + _exposed_note(cfg),
        why="An open proxy is abused within hours and, like SOCKS, is a common post-compromise change.",
        fix=["/ip proxy set enabled=no"],
        evidence=[e.raw],
    )


@rule("HL-021", "Scheduler or script fetches from the internet", "high", "exposure")
def r021(cfg: Config):
    hits = []
    for e in cfg.section("/system scheduler") + cfg.section("/system script"):
        body = (e.get("on-event") or "") + " " + (e.get("source") or "")
        if "fetch" in body.lower() and ("http" in body.lower() or "url=" in body.lower()):
            hits.append(e)
    if not hits:
        return None
    return dict(
        observed=f"{len(hits)} scheduler/script entr{'y' if len(hits) == 1 else 'ies'} use `/tool fetch` against a URL.",
        why="This is exactly how RouterOS botnets persist: a scheduler that re-downloads the "
            "payload after every reboot. It is also how legitimate config pulls work — so read "
            "the URL and decide.",
        fix=["/system scheduler print detail", "/system script print detail",
             "# remove anything you did not create:",
             "/system scheduler remove [find name=<name>]"],
        evidence=[e.raw[:200] for e in hits[:5]],
        caution="If this is your own provisioning script, keep it — but note the URL and pin it to HTTPS.",
    )


@rule("HL-022", "IPv6 enabled with no IPv6 input firewall", "high", "exposure")
def r022(cfg: Config):
    if not cfg.section("/ipv6 address") and not any(e.flag("disabled") is False for e in cfg.section("/ipv6 settings")):
        return None
    v6 = [e for e in cfg.section("/ipv6 firewall filter") if e.get("chain") == "input" and e.get("action") in ("drop", "reject")]
    if v6:
        return None
    return dict(
        observed="IPv6 addresses are configured but the IPv6 input chain has no drop rule.",
        why="Every IPv4 firewall rule above is irrelevant to an attacker who arrives over v6. "
            "This is the most common way a 'hardened' router is still open.",
        fix=["/ipv6 firewall filter",
             "add chain=input action=accept connection-state=established,related,untracked",
             "add chain=input action=drop connection-state=invalid",
             "add chain=input action=accept protocol=icmpv6",
             f"add chain=input action=accept in-interface-list=!{cfg.wan_interface_list() or 'WAN'}",
             f"add chain=input action=drop {_wan_scope(cfg)}"],
        evidence=[e.raw for e in cfg.section('/ipv6 address')[:3]],
    )


@rule("HL-023", "RoMON enabled", "low", "exposure")
def r023(cfg: Config):
    e = cfg.first("/tool romon")
    if not e or not e.flag("enabled"):
        return None
    if e.get("secrets"):
        return None
    return dict(
        observed="RoMON is enabled without a secret.",
        why="RoMON lets any RouterOS on the same L2 segment discover and connect to this one. "
            "Without a shared secret that includes a stranger's router at the tower.",
        fix=["/tool romon set secrets=<shared-secret>", "# or", "/tool romon set enabled=no"],
        evidence=[e.raw],
    )


@rule("HL-024", "No drop for invalid connections on input", "low", "exposure")
def r024(cfg: Config):
    if not _has_input_drop(cfg):
        return None  # HL-003 already says the whole chain is missing
    if any(e.get("action") == "drop" and (e.get("connection-state") or "") == "invalid" for e in _input_rules(cfg)):
        return None
    return dict(
        observed="The input chain never drops `connection-state=invalid`.",
        why="Cheap protection against state-table abuse and malformed packet floods.",
        fix=["/ip firewall filter add chain=input action=drop connection-state=invalid place-before=0 comment=\"hardline: drop invalid\""],
    )


@rule("HL-025", "www-ssl / api-ssl with the self-signed default", "info", "exposure")
def r025(cfg: Config):
    for name in ("www-ssl", "api-ssl"):
        svc = cfg.service(name)
        if svc and not svc.flag("disabled") and not svc.get("certificate"):
            return dict(
                observed=f"`{name}` is enabled without a certificate assigned.",
                why="Clients cannot verify the router, so the TLS is only protecting you from passive sniffing, not from a man-in-the-middle at the tower.",
                fix=[f"/ip service set {name} certificate=<cert-name>"],
                evidence=[svc.raw],
            )
    return None


# ── evidence rules ───────────────────────────────────────────────────────────

@rule("HL-030", "Logs stay on the router", "medium", "evidence")
def r030(cfg: Config):
    actions = cfg.section("/system logging action")
    remote = any(e.get("target") == "remote" and e.get("remote") for e in actions)
    rules_to_remote = any(e.get("action") not in (None, "memory", "disk", "echo") for e in cfg.section("/system logging"))
    if remote and rules_to_remote:
        return None
    return dict(
        observed="No logging action ships to a remote syslog host" if not remote
                 else "A remote logging action exists but no logging rule uses it.",
        why="The memory log holds a few hundred lines and is gone on reboot — which is the first "
            "thing an attacker does. If you cannot produce a log, an incident did not happen "
            "as far as an auditor or insurer is concerned.",
        fix=["/system logging action add name=hardline-syslog target=remote remote=<syslog-ip> remote-port=514 src-address=" + _mgmt_nets(cfg).split('/')[0].rsplit('.', 1)[0] + ".1",
             "/system logging add topics=system,error,critical,warning action=hardline-syslog",
             "/system logging add topics=info,!debug action=hardline-syslog"],
        evidence=[e.raw for e in actions[:3]],
    )


@rule("HL-031", "No NTP client", "low", "evidence")
def r031(cfg: Config):
    e = cfg.first("/system ntp client")
    if e and (e.flag("enabled") or e.get("servers") or e.get("primary-ntp")):
        return None
    return dict(
        observed="The NTP client is not enabled.",
        why="Without a clock, log timestamps are meaningless and certificates fail after a reboot. "
            "Evidence without time is not evidence.",
        fix=["/system ntp client set enabled=yes servers=pool.ntp.org",
             "/system clock set time-zone-name=Africa/Johannesburg"],
        evidence=[e.raw] if e else [],
    )


@rule("HL-032", "Nothing logs firewall drops from the WAN", "low", "evidence")
def r032(cfg: Config):
    if not _has_input_drop(cfg):
        return None
    if any(e.get("action") in ("drop", "reject") and e.flag("log") for e in _input_rules(cfg)):
        return None
    return dict(
        observed="The input-chain drop rule does not log.",
        why="Logging the final drop (with a prefix and rate-limit) is the cheapest intrusion "
            "sensor you will ever own. It is also the record you show after an incident.",
        fix=["/ip firewall filter set [find chain=input action=drop] log=yes log-prefix=\"WAN-DROP\""],
        caution="On a busy edge, ship logs off-box first (HL-030) or the memory log will churn.",
    )


@rule("HL-033", "Shared service account naming", "info", "evidence")
def r033(cfg: Config):
    generic = [e for e in cfg.section("/user") if e.cmd == "add" and e.get("group") == "full"
               and (e.get("name") or "").lower() in ("user", "test", "temp", "support", "tech", "noc", "engineer", "mikrotik", "root")]
    if not generic:
        return None
    return dict(
        observed="Full-privilege account(s) with generic names: " + ", ".join(e.get("name") or "?" for e in generic) + ".",
        why="A shared `noc` login means the log says `noc` did it. You cannot answer who.",
        fix=["/user add name=<firstname.lastname> group=full password=<pw>", "/user remove [find name=noc]"],
        evidence=[e.raw for e in generic[:5]],
    )


# ── runner ───────────────────────────────────────────────────────────────────

def run(cfg: Config) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES:
        res = r["fn"](cfg)
        if not res:
            continue
        sev = res.pop("severity", r["severity"])
        findings.append(Finding(id=r["id"], title=r["title"], severity=sev, axis=r["axis"], **res))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
    return findings
