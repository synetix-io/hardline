"""Parse a RouterOS `/export` into something rules can query.

The export format is line-oriented: a `/path` line opens a section, then
`add ...` / `set ...` lines carry key=value pairs. Long lines wrap with a
trailing backslash. Values may be quoted. `set` lines may target an item by
name, by index, or by `[ find key=value ]`.

Nothing here executes or evaluates config content. It is text in, dataclasses out.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

VERSION_RE = re.compile(r"by RouterOS\s+(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9]*))")
MODEL_RE = re.compile(r"^#\s*model\s*=\s*(.+)$")
KV_RE = re.compile(r"^([\w\-\.:/]+)=(.*)$", re.S)


class ParseError(ValueError):
    pass


@dataclass
class Entry:
    path: str
    cmd: str
    target: str | None
    args: dict[str, str]
    raw: str
    line: int

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.args.get(key, default)

    def flag(self, key: str) -> bool:
        return self.args.get(key, "no").lower() in ("yes", "true")


@dataclass
class Config:
    version: str | None = None
    model: str | None = None
    identity: str | None = None
    entries: list[Entry] = field(default_factory=list)
    line_count: int = 0

    def section(self, path: str) -> list[Entry]:
        return [e for e in self.entries if e.path == path]

    def find(self, path: str, cmd: str | None = None, **kv: str) -> list[Entry]:
        out = []
        for e in self.section(path):
            if cmd and e.cmd != cmd:
                continue
            if all(e.args.get(k) == v for k, v in kv.items()):
                out.append(e)
        return out

    def first(self, path: str, cmd: str | None = None, **kv: str) -> Entry | None:
        hits = self.find(path, cmd, **kv)
        return hits[0] if hits else None

    def has_section(self, path: str) -> bool:
        return any(e.path == path for e in self.entries)

    # ── convenience views used by several rules ───────────────────────────
    def service(self, name: str) -> Entry | None:
        """The `/ip service set <name> ...` entry, if the export mentions it."""
        for e in self.section("/ip service"):
            if e.cmd == "set" and e.target == name:
                return e
        return None

    def service_enabled(self, name: str, default: bool = True) -> bool:
        e = self.service(name)
        if e is None or "disabled" not in e.args:
            return default
        return not e.flag("disabled")

    def wan_interface_list(self) -> str | None:
        for e in self.section("/interface list"):
            if e.cmd == "add" and (e.get("name") or "").upper() == "WAN":
                return e.get("name")
        return None

    def wan_interfaces(self) -> list[str]:
        names: list[str] = []
        for e in self.section("/interface list member"):
            if (e.get("list") or "").upper() == "WAN" and e.get("interface"):
                names.append(e.get("interface"))  # type: ignore[arg-type]
        if not names:
            for e in self.section("/interface ethernet"):
                n = e.get("name") or ""
                if re.search(r"wan|uplink|internet|isp", n, re.I):
                    names.append(n)
            for e in self.section("/interface pppoe-client") + self.section("/interface lte"):
                if e.get("name"):
                    names.append(e.get("name"))  # type: ignore[arg-type]
        return names


def version_tuple(v: str | None) -> tuple[int, ...] | None:
    if not v:
        return None
    nums = re.findall(r"\d+", v.split("rc")[0].split("beta")[0])
    return tuple(int(n) for n in nums[:3]) if nums else None


def _tokenize(s: str) -> list[str]:
    """Split on whitespace, keeping quoted strings and `[ ... ]` groups intact."""
    tokens: list[str] = []
    buf: list[str] = []
    i, n = 0, len(s)
    depth = 0
    in_q = False
    while i < n:
        c = s[i]
        if in_q:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_q = False
        elif c == '"':
            in_q = True
            buf.append(c)
        elif c == "[":
            depth += 1
            buf.append(c)
        elif c == "]":
            depth = max(0, depth - 1)
            buf.append(c)
        elif c.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        tokens.append("".join(buf))
    return tokens


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v


def _join_continuations(text: str) -> list[tuple[int, str]]:
    """Return (first_line_number, logical_line) with backslash continuations joined."""
    out: list[tuple[int, str]] = []
    cur: list[str] = []
    start = 0
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        if not cur:
            start = idx
        if line.rstrip().endswith("\\"):
            cur.append(line.rstrip()[:-1].rstrip())
            continue
        cur.append(line.strip() if cur else line)
        out.append((start, " ".join(p.strip() for p in cur)))
        cur = []
    if cur:
        out.append((start, " ".join(p.strip() for p in cur)))
    return out


def parse(text: str) -> Config:
    if not text or not text.strip():
        raise ParseError("The export is empty.")
    if "\x00" in text[:4096]:
        raise ParseError("This looks like a binary .backup file. Hardline reads the text "
                         "output of `/export`, not `/system backup` files.")

    cfg = Config(line_count=text.count("\n") + 1)
    path: str | None = None
    saw_command = False

    for line_no, line in _join_continuations(text):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            m = VERSION_RE.search(s)
            if m and not cfg.version:
                cfg.version = m.group(1)
            m = MODEL_RE.match(s)
            if m and not cfg.model:
                cfg.model = m.group(1).strip()
            continue
        if s.startswith("/"):
            # A section header, or an inline command like `/system identity set name=X`
            tokens = _tokenize(s)
            cmd_idx = next((i for i, t in enumerate(tokens) if t in ("add", "set", "remove", "enable", "disable")), None)
            if cmd_idx is None:
                path = " ".join(tokens)
                continue
            path = " ".join(tokens[:cmd_idx])
            tokens = tokens[cmd_idx:]
        else:
            tokens = _tokenize(s)
        if not tokens or path is None:
            continue
        cmd, rest = tokens[0], tokens[1:]
        if cmd not in ("add", "set", "remove", "enable", "disable"):
            continue
        saw_command = True
        args: dict[str, str] = {}
        target_parts: list[str] = []
        for t in rest:
            m = KV_RE.match(t)
            if m and not t.startswith("["):
                args[m.group(1)] = _unquote(m.group(2))
            elif not args:
                target_parts.append(t)
            else:
                args[t] = "yes"  # bare flag
        target = " ".join(target_parts) if target_parts else None
        entry = Entry(path=path, cmd=cmd, target=target, args=args, raw=s, line=line_no)
        cfg.entries.append(entry)
        if path == "/system identity" and args.get("name"):
            cfg.identity = args["name"]

    if not saw_command:
        raise ParseError("No RouterOS commands found. Paste the output of `/export` "
                         "(Winbox: New Terminal → `/export`).")
    return cfg
