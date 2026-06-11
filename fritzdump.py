#!/usr/bin/env python3
"""
fritzdump.py - Live packet capture from a FRITZ!Box (e.g. 6591 Cable)

Streams the hidden packet capture of the box live into Wireshark, ntopng,
a pcap file, or stdout (to pipe into your own SIEM tool). Supports both the
old MD5 and the current PBKDF2 login (FRITZ!OS 7.24+ / 8.x).

Login data is read from a .env file (FRITZ_HOST / FRITZ_USER / FRITZ_PW),
or from CLI flags / environment variables.

Examples:
    ./fritzdump.py --list                          # list interfaces (find IDs)
    ./fritzdump.py --iface 2-1 --to wireshark      # WAN live into Wireshark
    ./fritzdump.py --iface 1-0 --to ntopng         # LAN live into ntopng
    ./fritzdump.py --iface 2-1 --to capture.pcap   # write to a file
    ./fritzdump.py --iface 2-1 --to - | siem-tool  # raw pcap to stdout

Notes:
  * Create a dedicated FRITZ!Box user only for capturing.
  * The user only needs the "FRITZ!Box settings" permission.
  * For password-only login (no username) use --user dslf-config.
  * Only capture your own network.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import html as html_lib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

DEFAULT_HOST = "fritz.box"
BASE_DIR = Path(__file__).resolve().parent
DUMP_DIR = BASE_DIR / "dumps"
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")
MAX_FILTER_LEN = 512
# Whitelist of characters allowed in a pcap/BPF filter. Covers the BPF grammar
# (host/port/net/proto, ranges, arithmetic, logic) while rejecting quotes,
# backticks, ';', '$' and other shell/markup metacharacters as defense in depth.
FILTER_RE = re.compile(r"^[A-Za-z0-9 .,_:/()\[\]!=<>&|+*\-]*$")
MAX_TEXT_RESPONSE = 1024 * 1024
MAX_ITERATIONS = 1_000_000
# Largest packet record we accept while redacting. Matches the box's snaplen
# ceiling; anything bigger means a desynced/corrupt stream, so we abort rather
# than buffer unbounded data.
MAX_CAPTURE_RECORD = 262144
PBKDF2_CHALLENGE_RE = re.compile(
    r"^2\$(?P<iter1>[0-9]{1,7})\$(?P<salt1>[0-9a-fA-F]{16,128})"
    r"\$(?P<iter2>[0-9]{1,7})\$(?P<salt2>[0-9a-fA-F]{16,128})$"
)
OLD_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")


def load_dotenv(path: str | None = None) -> dict[str, str]:
    """Read a .env (KEY=VALUE) without exporting secrets to this process env."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    values: dict[str, str] = {}
    if not os.path.exists(path):
        return values
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                val = val.strip()
                if len(val) >= 2:
                    if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
                        val = val[1:-1]
                values[key.strip()] = val
    except OSError:
        pass
    return values


class Settings:
    """Reads configuration from the process environment first, then .env.

    Secrets in the .env file are never exported into ``os.environ``; they are
    only looked up on demand here, so they don't leak into child processes.
    """

    def __init__(self, dotenv: dict[str, str]):
        self._dotenv = dotenv

    def get(self, name: str, default: str | None = None) -> str | None:
        return os.environ.get(name, self._dotenv.get(name, default))

    def get_bool(self, name: str, default: bool = False) -> bool:
        value = self.get(name)
        if value is None:
            return default
        return value.lower() in ("1", "true", "yes")


class RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent redirects to non-http(s) schemes like file:// or gopher://."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlparse(newurl)
        if parts.scheme not in ("http", "https"):
            raise urllib.error.HTTPError(newurl, code, f"Unsafe redirect to {parts.scheme}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(scheme: str, insecure_tls: bool = False, cacert: str | None = None):
    """urllib opener; HTTPS certificates are verified unless explicitly disabled.

    If ``cacert`` is given, it is used as the trust anchor instead of the system
    store. This lets you pin the FRITZ!Box's own (self-signed) certificate and
    keep verification on, so HTTPS protects against man-in-the-middle attacks
    without falling back to ``--https-insecure``.
    """
    handlers = [RestrictedRedirectHandler()]
    if scheme == "https":
        ctx = ssl.create_default_context(cafile=cacert) if cacert else ssl.create_default_context()
        if insecure_tls:
            print(
                "WARNING: HTTPS certificate verification is DISABLED. The "
                "connection is encrypted but NOT authenticated - anyone on your "
                "LAN/Wi-Fi can impersonate the box (man-in-the-middle) and "
                "capture the session and all recorded packets. Prefer pinning "
                "the box certificate with --cacert / FRITZ_CACERT instead.",
                file=sys.stderr,
            )
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def read_limited_text(resp, limit: int = MAX_TEXT_RESPONSE) -> str:
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"HTTP response too large (>{limit} bytes)")
    return data.decode("utf-8", "replace")


def http_get(opener, url: str, binary: bool = False, timeout: int | None = 10,
             max_text: int = MAX_TEXT_RESPONSE):
    req = urllib.request.Request(url, headers={"User-Agent": "fritzcap/1.0"})
    resp = opener.open(req, timeout=timeout)
    return resp if binary else read_limited_text(resp, max_text)


def validate_host(host: str) -> None:
    if not HOST_RE.fullmatch(host) or any(ch in host for ch in "/\\@?#"):
        raise ValueError("Invalid host. Use only a hostname or IP address.")


def validate_capture_args(args: argparse.Namespace) -> None:
    if args.iface and not IFACE_RE.fullmatch(args.iface):
        raise ValueError("Invalid interface ID.")
    if args.snaplen:
        if not args.snaplen.isdigit() or not 64 <= int(args.snaplen) <= 262144:
            raise ValueError("Invalid snaplen. Use a number between 64 and 262144.")
    if len(args.filter) > MAX_FILTER_LEN or not FILTER_RE.fullmatch(args.filter):
        raise ValueError(
            "Invalid capture filter. Allowed: letters, digits, spaces and "
            ". , _ : / ( ) [ ] ! = < > & | + * -"
        )


def read_password_file(path_text: str) -> str:
    raw_path = Path(path_text).expanduser()
    if raw_path.is_symlink():
        raise ValueError("Password file must be a regular file, not a symlink.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(raw_path, flags)
    except FileNotFoundError as exc:
        raise ValueError("Password file does not exist.") from exc
    except OSError as exc:
        raise ValueError(f"Could not open password file: {exc}") from exc
    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Password file must be a regular file.")
        if st.st_mode & 0o077:
            raise ValueError("Password file must not be readable by group/others.")
        password = fh.readline(1024).rstrip("\r\n")
    if not password:
        raise ValueError("Password file is empty.")
    return password


def safe_capture_path(to: str) -> Path:
    path = Path(to)
    allowed_roots = (BASE_DIR, DUMP_DIR.resolve(strict=False))
    if path.is_absolute():
        resolved = path.resolve(strict=False)
    else:
        resolved = (BASE_DIR / path).resolve(strict=False)
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        raise ValueError("Capture output must stay inside the project dumps directory.")
    if resolved.name.startswith(".") or resolved.suffix.lower() not in (".pcap", ".pcapng", ".eth"):
        raise ValueError("Capture output must be a visible .pcap, .pcapng, or .eth file.")
    if (BASE_DIR / ".git").resolve(strict=False) in resolved.parents:
        raise ValueError("Refusing to write inside .git.")
    if resolved.exists() and not resolved.is_file():
        raise ValueError("Capture output path is not a regular file.")
    if not resolved.parent.exists():
        raise ValueError("Capture output directory does not exist.")
    for parent in (resolved.parent, *resolved.parent.parents):
        if parent in allowed_roots:
            break
        if parent.is_symlink():
            raise ValueError("Refusing to write through a symlinked directory.")
    return resolved


def get_challenge(opener, base: str) -> tuple[str, int]:
    """Fetch challenge + block time from login_sid.lua."""
    xml = http_get(opener, f"{base}/login_sid.lua?version=2")
    challenge = re.search(r"<Challenge>(.*?)</Challenge>", xml)
    blocktime = re.search(r"<BlockTime>(.*?)</BlockTime>", xml)
    if not challenge:
        raise RuntimeError("No challenge received - wrong IP/host?")
    return challenge.group(1), int(blocktime.group(1)) if blocktime else 0


def solve_challenge(challenge: str, password: str, allow_legacy: bool = False) -> str:
    """Compute the login response. PBKDF2 for new, MD5 for old firmware.

    Modern FRITZ!OS (7.24+) sends a ``2$...`` PBKDF2 challenge and that path is
    always used. Pre-7.24 firmware uses an MD5 challenge-response, which is the
    only scheme those boxes accept. Because a downgrade to the weaker MD5 scheme
    could be forced by a man-in-the-middle on a plain-HTTP link, the legacy path
    is refused unless ``allow_legacy`` is explicitly set.
    """
    if challenge.startswith("2$"):
        # Format: 2$<iter1>$<salt1>$<iter2>$<salt2>
        m = PBKDF2_CHALLENGE_RE.match(challenge)
        if not m:
            raise RuntimeError("Invalid PBKDF2 challenge format.")
        it1, it2 = int(m.group("iter1")), int(m.group("iter2"))
        if it1 > MAX_ITERATIONS or it2 > MAX_ITERATIONS:
            raise RuntimeError(f"PBKDF2 iterations too high ({it1}/{it2}).")
        salt1, salt2 = bytes.fromhex(m.group("salt1")), bytes.fromhex(m.group("salt2"))
        hash1 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt1, it1)
        hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, it2)
        return f"{m.group('salt2')}${hash2.hex()}"
    if not allow_legacy:
        raise RuntimeError(
            "Box offered the legacy MD5 login (pre-FRITZ!OS 7.24). This weaker "
            "scheme is refused by default to prevent a forced downgrade. If your "
            "box genuinely runs old firmware, re-run with --allow-legacy-login "
            "(or FRITZ_ALLOW_LEGACY=true) and prefer HTTPS so the exchange can't "
            "be observed."
        )
    # Legacy: MD5 over (challenge + "-" + password) in UTF-16LE. The algorithm is
    # mandated by the old FRITZ!Box protocol (the box computes the same MD5 and
    # compares); it is not a password-at-rest hash and cannot be strengthened
    # without breaking login on that firmware. Gated behind --allow-legacy-login.
    if not OLD_CHALLENGE_RE.fullmatch(challenge):
        raise RuntimeError("Invalid MD5 challenge format.")
    raw = f"{challenge}-{password}".encode("utf-16-le")
    return f"{challenge}-{hashlib.md5(raw).hexdigest()}"  # noqa: S324 - legacy protocol


def get_sid(opener, base: str, user: str, response: str) -> str:
    params = urllib.parse.urlencode({"username": user, "response": response})
    xml = http_get(opener, f"{base}/login_sid.lua?version=2&{params}")
    m = re.search(r"<SID>(.*?)</SID>", xml)
    sid = m.group(1) if m else "0" * 16
    if set(sid) == {"0"}:
        raise RuntimeError(
            "Login failed. Check user/password and that the user has the "
            "'FRITZ!Box settings' permission (or use --user dslf-config)."
        )
    return sid


def sanitize_terminal(text: str) -> str:
    """Remove control characters and terminal escape sequences."""
    return "".join(ch for ch in text if ch.isprintable())


def _clean_label(text: str) -> str:
    """Strip HTML tags from an interface label and collapse its whitespace."""
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html_lib.unescape(text)).strip()


def _interfaces_from_json(raw: str):
    """Yield (id, label) pairs from the data.lua JSON snapshot (best source)."""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return
    interfaces = payload.get("data", {}).get("snapshot", {}).get("interfaces", [])
    for item in interfaces:
        if not isinstance(item, dict):
            continue
        iid = item.get("name") or item.get("id") or item.get("ifaceorminor")
        if not iid:
            continue
        label = " ".join(str(part) for part in (
            item.get("kind"), item.get("ifacename"),
            item.get("displayname"), item.get("description"),
        ) if part)
        yield iid, label


def _interfaces_from_buttons(raw: str):
    """Yield (id, label) pairs from the HTML capture table's Start buttons."""
    for row in re.finditer(r"<tr\b.*?</tr>", raw, flags=re.IGNORECASE | re.DOTALL):
        tr = row.group(0)
        btn = re.search(
            r"<button\b(?=[^>]*\bname=[\"']start[\"'])(?=[^>]*\bvalue=[\"']([^\"']+)[\"'])",
            tr,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not btn:
            continue
        th = re.search(r"<th\b[^>]*>(.*?)</th>", tr, flags=re.IGNORECASE | re.DOTALL)
        yield html_lib.unescape(btn.group(1)), _clean_label(th.group(1)) if th else ""


def _interfaces_from_urls(raw: str):
    """Yield (id, label) pairs from leftover ifaceorminor=... links (last resort)."""
    for m in re.finditer(r"ifaceorminor=([^&\"'\s>]+)", raw):
        label = _clean_label(raw[max(0, m.start() - 220):m.start()])[-55:]
        yield m.group(1), label


def list_interfaces(opener, base: str, sid: str) -> None:
    """Fetch the capture page and print the interface IDs it advertises.

    FRITZ!OS versions render this page differently, so three sources are tried
    in order of reliability: the JSON snapshot, the HTML Start buttons, and any
    remaining ifaceorminor=... links. The first occurrence of an ID wins; later
    duplicates from another source are ignored.
    """
    data = urllib.parse.urlencode({"sid": sid, "page": "cap", "lang": "en"}).encode()
    req = urllib.request.Request(f"{base}/data.lua", data=data,
                                 headers={"User-Agent": "fritzcap/1.0"})
    raw = read_limited_text(opener.open(req, timeout=10))

    seen, rows = set(), []
    for source in (_interfaces_from_json, _interfaces_from_buttons, _interfaces_from_urls):
        for iid, label in source(raw):
            if iid in seen:
                continue
            seen.add(iid)
            rows.append((iid, label))

    if not rows:
        print("No interface IDs found. Open the capture page in a browser and "
              "read the IDs from the page source.", file=sys.stderr)
        return
    print(f"{'ID (--iface)':<14}description (hint)")
    print("-" * 60)
    for iid, label in rows:
        print(f"{iid:<14}...{sanitize_terminal(label)}")


class PcapRedactor:
    """Streaming pcap filter that strips packet payloads but keeps the headers.

    The FRITZ!Box streams a normal pcap (global header + per-packet records).
    When redaction is enabled we parse that stream on the fly and truncate every
    frame to the end of its L2-L4 headers: Ethernet (MAC addresses), IPv4/IPv6
    (IP addresses, protocol), and TCP/UDP/ICMP (ports, flags) are preserved, the
    application payload is dropped. Each record keeps its original ``orig_len``,
    so you still see how big a message was and between whom it flowed -- but not
    what was inside. To downstream tools this looks exactly like a capture taken
    with a small snaplen (Wireshark shows "[Packet size limited during capture]").

    The box emits the "modified"/patched libpcap format (magic a1b2cd34, 24-byte
    record headers). Many readers reject that magic -- notably scapy, which the
    GDEF pipeline uses, raises "Not a supported capture file". So we NORMALIZE the
    output to a standard us-resolution pcap: the modified magic is rewritten to
    its standard equivalent and the 8 extra per-record bytes (ifindex/pkt_type/
    pad, unused for flow accounting) are dropped. Standard input magics pass
    through unchanged (rewriting an ns magic to us would mislabel timestamps).

    Chunks from the box do not align with packet boundaries, so input is buffered
    until a full record is available.
    """

    # global-header magic -> (struct endian prefix, per-record header length).
    # The classic us/ns formats use a 16-byte record header; the FRITZ!Box's
    # "modified" format (a1b2cd34) uses 24 (the standard 16 + ifindex/protocol/
    # pkt_type/pad). We accept all of them, else redaction aborts on a box stream.
    MAGIC = {
        b"\xa1\xb2\xc3\xd4": (">", 16), b"\xd4\xc3\xb2\xa1": ("<", 16),  # us-resolution
        b"\xa1\xb2\x3c\x4d": (">", 16), b"\x4d\x3c\xb2\xa1": ("<", 16),  # ns-resolution
        b"\xa1\xb2\xcd\x34": (">", 24), b"\x34\xcd\xb2\xa1": ("<", 24),  # modified
    }
    # Modified magic -> equivalent standard us magic, written on output so common
    # readers (scapy, tshark) accept the redacted stream. Standard magics are not
    # listed: they are emitted verbatim to keep their us/ns resolution intact.
    NORMALIZE = {
        b"\xa1\xb2\xcd\x34": b"\xa1\xb2\xc3\xd4", b"\x34\xcd\xb2\xa1": b"\xd4\xc3\xb2\xa1",
    }

    def __init__(self, write):
        self._write = write
        self._buf = bytearray()
        self._endian = None
        self._rec = None
        self._rec_hdr_len = None
        self._linktype = None
        self._header_done = False

    def feed(self, chunk):
        self._buf += chunk
        if not self._header_done:
            if len(self._buf) < 24:
                return
            magic = bytes(self._buf[:4])
            info = self.MAGIC.get(magic)
            if info is None:
                raise RuntimeError(
                    "Cannot redact: stream is not a recognized pcap (bad magic). "
                    "The box may be sending pcapng; capture without --redact."
                )
            self._endian, self._rec_hdr_len = info
            self._rec = struct.Struct(self._endian + "IIII")
            (self._linktype,) = struct.unpack(self._endian + "I", self._buf[20:24])
            # Rewrite a "modified" magic to its standard equivalent (see NORMALIZE);
            # the rest of the 24-byte global header is identical across formats.
            self._write(self.NORMALIZE.get(magic, magic) + bytes(self._buf[4:24]))
            del self._buf[:24]
            self._header_done = True

        hdr_len = self._rec_hdr_len
        while len(self._buf) >= hdr_len:
            ts_sec, ts_usec, incl_len, orig_len = self._rec.unpack(self._buf[:16])
            if incl_len > MAX_CAPTURE_RECORD:
                raise RuntimeError(
                    f"Cannot redact: implausible packet length ({incl_len} bytes); "
                    "stream is corrupt or out of sync."
                )
            if len(self._buf) < hdr_len + incl_len:
                return  # wait for the rest of this packet
            # Drop the "modified" format's 8 extra header bytes (ifindex etc.) so
            # the output is a standard 16-byte-record pcap; for standard input
            # hdr_len is already 16 and there is nothing extra to drop.
            frame = bytes(self._buf[hdr_len:hdr_len + incl_len])
            del self._buf[:hdr_len + incl_len]
            kept = self._redact(frame)
            self._write(self._rec.pack(ts_sec, ts_usec, len(kept), orig_len))
            self._write(kept)

    def _redact(self, frame):
        """Return the leading header bytes of ``frame`` to keep (payload dropped)."""
        if self._linktype == 1:        # LINKTYPE_ETHERNET (wired bridge)
            return self._redact_ethernet(frame)
        if self._linktype == 105:      # LINKTYPE_IEEE802_11 (Wi-Fi interfaces)
            return self._redact_dot11(frame)
        return frame[:54]              # unknown link type: conservative fixed prefix

    def _redact_ethernet(self, frame):
        n = len(frame)
        if n < 14:
            return frame
        etype = int.from_bytes(frame[12:14], "big")
        off = 14
        # Walk one or more VLAN tags (802.1Q / QinQ).
        while etype in (0x8100, 0x88A8, 0x9100) and n >= off + 4:
            etype = int.from_bytes(frame[off + 2:off + 4], "big")
            off += 4
        return self._keep_from_l3(frame, off, etype, n)

    def _redact_dot11(self, frame):
        """Keep the 802.11 MAC header + LLC/SNAP + L3/L4 headers; drop payload.

        The FRITZ!Box Wi-Fi capture streams raw 802.11 (Dot11/LLC/SNAP/IP). The
        MAC header length is variable, so compute it from the frame-control field
        before locating the SNAP-encapsulated EtherType and the IP header."""
        n = len(frame)
        if n < 24:
            return frame
        fc0, fc1 = frame[0], frame[1]
        ftype = (fc0 >> 2) & 0x03
        subtype = (fc0 >> 4) & 0x0F
        # Only data frames (type 2) encapsulate an LLC/SNAP+IP payload. Management
        # and control frames carry no IP to hide, so keep them verbatim.
        if ftype != 2:
            return frame
        # Null-data frames (subtypes 4 and 12) have no payload at all.
        if subtype in (4, 12):
            return frame
        hdr = 24
        if (fc1 & 0x03) == 0x03:    # ToDS && FromDS -> 4-address header (+addr4)
            hdr += 6
        if subtype & 0x08:          # QoS data subtypes (8..15) carry a QoS control field
            hdr += 2
            if fc1 & 0x80:          # Order bit set on QoS data -> HT Control field
                hdr += 4
        # LLC/SNAP: aa-aa-03 OUI 00-00-00 then the encapsulated EtherType.
        if n >= hdr + 8 and frame[hdr:hdr + 2] == b"\xaa\xaa":
            etype = int.from_bytes(frame[hdr + 6:hdr + 8], "big")
            return self._keep_from_l3(frame, hdr + 8, etype, n)
        return frame[:hdr]          # no recognizable SNAP: keep only the MAC header

    def _keep_from_l3(self, frame, off, etype, n):
        """Given the L3 start offset and EtherType, return the bytes to keep
        (through the end of the L4 header; payload dropped)."""
        if etype == 0x0800 and n >= off + 20:  # IPv4
            ihl = max((frame[off] & 0x0F) * 4, 20)
            return frame[:self._l4_keep(frame, off + ihl, frame[off + 9], n)]
        if etype == 0x86DD and n >= off + 40:  # IPv6 (no extension-header walk)
            return frame[:self._l4_keep(frame, off + 40, frame[off + 6], n)]
        # ARP and other small control frames carry no payload to hide: keep them.
        if n <= 64:
            return frame
        return frame[:off]  # unknown large frame: keep only the L2 header

    @staticmethod
    def _l4_keep(frame, ip_end, proto, n):
        """End offset to keep for a given L4 protocol (header only, no payload)."""
        if proto == 6 and n >= ip_end + 20:  # TCP: data offset gives header length
            doff = max((frame[ip_end + 12] >> 4) * 4, 20)
            return min(ip_end + doff, n)
        if proto in (17, 1, 58):  # UDP / ICMPv4 / ICMPv6: 8-byte header
            return min(ip_end + 8, n)
        return min(ip_end, n)  # other protocols: keep the IP header only


def open_target(to: str):
    """Return (write_fn, flush_fn, close_fn, proc) depending on the target.

    flush_fn must be called after every write so a *consumer* tailing the target
    (e.g. the GDEF-L1NK hub reading the pcap off disk) sees each packet as it is
    captured. Without it the file's userspace block buffer holds tens of seconds
    of low-rate traffic and only spills to disk when full — which the reader sees
    as long silences punctuated by sudden bursts."""
    # Isolate subprocess environment: only pass necessary PATH and TERM
    clean_env = {"PATH": os.environ.get("PATH", ""), "TERM": os.environ.get("TERM", "dumb")}

    if to == "wireshark":
        wireshark = shutil.which("wireshark")
        if not wireshark:
            raise RuntimeError("wireshark not found in PATH.")
        proc = subprocess.Popen([wireshark, "-k", "-i", "-"],
                                stdin=subprocess.PIPE, env=clean_env)
        return proc.stdin.write, proc.stdin.flush, proc.stdin.close, proc
    if to == "ntopng":
        ntopng = shutil.which("ntopng")
        if not ntopng:
            raise RuntimeError("ntopng not found in PATH.")
        proc = subprocess.Popen([ntopng, "-i", "-"],
                                stdin=subprocess.PIPE, env=clean_env)
        return proc.stdin.write, proc.stdin.flush, proc.stdin.close, proc
    if to in ("-", "stdout"):
        return sys.stdout.buffer.write, sys.stdout.buffer.flush, lambda: None, None
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(safe_capture_path(to), flags, 0o600)
    f = os.fdopen(fd, "wb")
    return f.write, f.flush, f.close, None


def build_parser(settings: Settings) -> argparse.ArgumentParser:
    """Build the CLI parser; defaults fall back to .env / environment values."""
    ap = argparse.ArgumentParser(description="Live capture from a FRITZ!Box")
    ap.add_argument("--host", default=settings.get("FRITZ_HOST", DEFAULT_HOST),
                    help="box host/IP (default from .env / fritz.box)")
    ap.add_argument("--https", action="store_true",
                    default=settings.get_bool("FRITZ_HTTPS"),
                    help="use HTTPS instead of HTTP (or FRITZ_HTTPS=true in .env)")
    ap.add_argument("--https-insecure", action="store_true",
                    default=settings.get_bool("FRITZ_HTTPS_INSECURE"),
                    help="disable HTTPS certificate verification (unsafe; prefer --cacert)")
    ap.add_argument("--cacert", default=settings.get("FRITZ_CACERT"),
                    help="PEM file to verify the box's HTTPS cert against "
                         "(pin a self-signed cert); or FRITZ_CACERT in .env")
    ap.add_argument("--user", default=settings.get("FRITZ_USER"),
                    help="FRITZ!Box user (or dslf-config); else FRITZ_USER from .env")
    ap.add_argument("--password-file",
                    help="read password from a local file instead of .env/prompt")
    ap.add_argument("--iface", help="interface ID, e.g. 2-1 (WAN) or 1-0 (LAN bridge)")
    ap.add_argument("--snaplen", default="", help="snaplen (empty = full)")
    ap.add_argument("--filter", default="", help="pcap filter, e.g. 'host 1.2.3.4'")
    ap.add_argument("--to", default="-",
                    help="target: wireshark | ntopng | <file.pcap> | - (stdout)")
    ap.add_argument("--list", action="store_true", help="only list interfaces")
    ap.add_argument("--redact", action="store_true",
                    default=settings.get_bool("FRITZ_REDACT"),
                    help="strip packet payloads, keep only headers (who/where/"
                         "size, not content); or FRITZ_REDACT=true in .env")
    ap.add_argument("--allow-legacy-login", action="store_true",
                    default=settings.get_bool("FRITZ_ALLOW_LEGACY"),
                    help="permit the weak pre-7.24 MD5 login (refused by default "
                         "to block downgrades); or FRITZ_ALLOW_LEGACY=true in .env")
    return ap


def resolve_password(args: argparse.Namespace, settings: Settings) -> str:
    """Get the password from --password-file, then .env, then an interactive prompt."""
    if args.password_file:
        try:
            return read_password_file(args.password_file)
        except ValueError as exc:
            sys.exit(f"ERROR: {exc}")
    return settings.get("FRITZ_PW") or getpass.getpass("FRITZ!Box password: ")


def prepare_transport(args: argparse.Namespace) -> str:
    """Validate the transport options and return the base URL for the box."""
    scheme = "https" if args.https else "http"
    if scheme == "http":
        print(
            "WARNING: using plain HTTP. Your session token and ALL captured "
            "packets travel your LAN/Wi-Fi unencrypted and can be read by "
            "anyone on the network. Use HTTPS (--https, ideally with --cacert).",
            file=sys.stderr,
        )
    if args.cacert:
        if args.https_insecure:
            sys.exit("ERROR: use either --cacert or --https-insecure, not both.")
        if not args.https:
            sys.exit("ERROR: --cacert requires --https (or FRITZ_HTTPS=true).")
        if not os.path.isfile(args.cacert):
            sys.exit(f"ERROR: CA cert file not found: {args.cacert}")
    return f"{scheme}://{args.host}"


def login(opener, base: str, user: str, password: str, allow_legacy: bool) -> str:
    """Run the full challenge/response handshake and return the session ID."""
    challenge, blocktime = get_challenge(opener, base)
    if blocktime:
        print(f"Note: box reports BlockTime {blocktime}s (too many failed logins).",
              file=sys.stderr)
    response = solve_challenge(challenge, password, allow_legacy)
    return get_sid(opener, base, user, response)


def run_capture(opener, base: str, sid: str, args: argparse.Namespace) -> bool:
    """Stream the live capture to the chosen target until stopped.

    Returns True if the capture ended with an error (so the caller can exit
    with a non-zero status), False on a clean stop.
    """
    start_query = urllib.parse.urlencode({
        "ifaceorminor": args.iface, "snaplen": args.snaplen,
        "filter": args.filter, "capture": "Start", "sid": sid,
    })
    cap_url = f"{base}/cgi-bin/capture_notimeout?{start_query}"
    stop_url = f"{base}/cgi-bin/capture_notimeout?capture=Stop&sid={sid}&ifaceorminor={args.iface}"

    write, flush, close, proc = open_target(args.to)
    if args.redact:
        write = PcapRedactor(write).feed
        print("[*] Redaction ON: payloads stripped; only packet headers "
              "(addresses, ports, sizes) are recorded.", file=sys.stderr)

    stop_requested = False
    capture_error = None

    def request_stop(*_):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    print(f"Capture running on {args.iface} -> {args.to}. Stop with Ctrl-C.",
          file=sys.stderr)
    try:
        resp = http_get(opener, cap_url, binary=True, timeout=None)
        while not stop_requested:
            # read1() hands back whatever one socket/chunk read yields instead of
            # blocking until a full 65 KB has accumulated — on a low-rate link that
            # accumulation is exactly what made the capture arrive in bursts. Pair
            # it with flush() so each packet reaches the target the moment it lands.
            chunk = resp.read1(65536)
            if not chunk:
                break
            write(chunk)
            flush()
    except BrokenPipeError:
        pass
    except Exception as exc:  # noqa: BLE001
        capture_error = exc
        msg = re.sub(r"sid=[0-9a-f]{16,64}", "sid=***HIDDEN***", str(exc))
        print(f"\nERROR: {msg}", file=sys.stderr)
    finally:
        if not stop_requested:
            print("\n[*] Stopping capture...", file=sys.stderr)
        _quietly(lambda: http_get(opener, stop_url, binary=True, timeout=5).read(1024))
        _quietly(close)
        if proc:
            _quietly(proc.terminate)
    return capture_error is not None


def _quietly(action: Callable[[], object]) -> None:
    """Run a best-effort cleanup action, ignoring any error it raises."""
    try:
        action()
    except Exception:  # noqa: BLE001
        pass


def main() -> None:
    settings = Settings(load_dotenv())
    args = build_parser(settings).parse_args()

    if not args.user:
        sys.exit("No user. Set FRITZ_USER in .env or use --user.")
    try:
        validate_host(args.host)
        validate_capture_args(args)
    except ValueError as exc:
        sys.exit(f"ERROR: {exc}")

    base = prepare_transport(args)
    password = resolve_password(args, settings)
    opener = build_opener("https" if args.https else "http",
                          args.https_insecure, args.cacert)

    sid = login(opener, base, args.user, password, args.allow_legacy_login)
    print("Login ok.", file=sys.stderr)

    if args.list:
        list_interfaces(opener, base, sid)
        return
    if not args.iface:
        sys.exit("Please provide --iface (or run --list first).")

    if run_capture(opener, base, sid, args):
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, urllib.error.URLError, ssl.SSLError) as exc:
        sys.exit(f"ERROR: {exc}")
