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


def load_dotenv(path=None):
    """Read a .env (KEY=VALUE) without exporting secrets to this process env."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    values = {}
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


class RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent redirects to non-http(s) schemes like file:// or gopher://."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlparse(newurl)
        if parts.scheme not in ("http", "https"):
            raise urllib.error.HTTPError(newurl, code, f"Unsafe redirect to {parts.scheme}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(scheme, insecure_tls=False, cacert=None):
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


def read_limited_text(resp, limit=MAX_TEXT_RESPONSE):
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"HTTP response too large (>{limit} bytes)")
    return data.decode("utf-8", "replace")


def http_get(opener, url, binary=False, timeout=10, max_text=MAX_TEXT_RESPONSE):
    req = urllib.request.Request(url, headers={"User-Agent": "fritzcap/1.0"})
    resp = opener.open(req, timeout=timeout)
    return resp if binary else read_limited_text(resp, max_text)


def validate_host(host):
    if not HOST_RE.fullmatch(host) or any(ch in host for ch in "/\\@?#"):
        raise ValueError("Invalid host. Use only a hostname or IP address.")


def validate_capture_args(args):
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


def read_password_file(path_text):
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


def safe_capture_path(to):
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


def get_challenge(opener, base):
    """Fetch challenge + block time from login_sid.lua."""
    xml = http_get(opener, f"{base}/login_sid.lua?version=2")
    challenge = re.search(r"<Challenge>(.*?)</Challenge>", xml)
    blocktime = re.search(r"<BlockTime>(.*?)</BlockTime>", xml)
    if not challenge:
        raise RuntimeError("No challenge received - wrong IP/host?")
    return challenge.group(1), int(blocktime.group(1)) if blocktime else 0


def solve_challenge(challenge, password):
    """Compute the login response. PBKDF2 for new, MD5 for old firmware."""
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
    # Old: MD5 over (challenge + "-" + password) in UTF-16LE
    if not OLD_CHALLENGE_RE.fullmatch(challenge):
        raise RuntimeError("Invalid MD5 challenge format.")
    raw = f"{challenge}-{password}".encode("utf-16-le")
    return f"{challenge}-{hashlib.md5(raw).hexdigest()}"


def get_sid(opener, base, user, response):
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


def sanitize_terminal(text):
    """Remove control characters and terminal escape sequences."""
    return "".join(ch for ch in text if ch.isprintable())


def list_interfaces(opener, base, sid):
    """Parse the capture page response for interface IDs."""
    data = urllib.parse.urlencode({"sid": sid, "page": "cap", "lang": "en"}).encode()
    req = urllib.request.Request(f"{base}/data.lua", data=data,
                                 headers={"User-Agent": "fritzcap/1.0"})
    raw = read_limited_text(opener.open(req, timeout=10))

    seen, rows = set(), []

    def clean_label(text):
        text = re.sub(r"<[^>]+>", " ", text)
        return re.sub(r"\s+", " ", html_lib.unescape(text)).strip()

    try:
        payload = json.loads(raw)
        interfaces = payload.get("data", {}).get("snapshot", {}).get("interfaces", [])
    except json.JSONDecodeError:
        interfaces = []

    for item in interfaces:
        if not isinstance(item, dict):
            continue
        iid = item.get("name") or item.get("id") or item.get("ifaceorminor")
        if not iid or iid in seen:
            continue
        seen.add(iid)
        label_parts = [
            item.get("kind"),
            item.get("ifacename"),
            item.get("displayname"),
            item.get("description"),
        ]
        label = " ".join(str(part) for part in label_parts if part)
        rows.append((iid, label))

    for m in re.finditer(r"<tr\b.*?</tr>", raw, flags=re.IGNORECASE | re.DOTALL):
        tr = m.group(0)
        btn = re.search(
            r"<button\b(?=[^>]*\bname=[\"']start[\"'])(?=[^>]*\bvalue=[\"']([^\"']+)[\"'])",
            tr,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not btn:
            continue
        iid = html_lib.unescape(btn.group(1))
        if iid in seen:
            continue
        seen.add(iid)
        th = re.search(r"<th\b[^>]*>(.*?)</th>", tr, flags=re.IGNORECASE | re.DOTALL)
        rows.append((iid, clean_label(th.group(1)) if th else ""))

    for m in re.finditer(r"ifaceorminor=([^&\"'\s>]+)", raw):
        iid = m.group(1)
        if iid in seen:
            continue
        seen.add(iid)
        label = clean_label(raw[max(0, m.start() - 220):m.start()])[-55:]
        rows.append((iid, label))

    if not rows:
        print("No interface IDs found. Open the capture page in a browser and "
              "read the IDs from the page source.", file=sys.stderr)
        return
    print(f"{'ID (--iface)':<14}description (hint)")
    print("-" * 60)
    for iid, label in rows:
        label = sanitize_terminal(label)
        print(f"{iid:<14}...{label}")


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

    Chunks from the box do not align with packet boundaries, so input is buffered
    until a full record is available.
    """

    MAGIC = {
        b"\xa1\xb2\xc3\xd4": ">", b"\xd4\xc3\xb2\xa1": "<",  # us-resolution
        b"\xa1\xb2\x3c\x4d": ">", b"\x4d\x3c\xb2\xa1": "<",  # ns-resolution
    }

    def __init__(self, write):
        self._write = write
        self._buf = bytearray()
        self._endian = None
        self._rec = None
        self._linktype = None
        self._header_done = False

    def feed(self, chunk):
        self._buf += chunk
        if not self._header_done:
            if len(self._buf) < 24:
                return
            magic = bytes(self._buf[:4])
            self._endian = self.MAGIC.get(magic)
            if self._endian is None:
                raise RuntimeError(
                    "Cannot redact: stream is not a recognized pcap (bad magic). "
                    "The box may be sending pcapng; capture without --redact."
                )
            self._rec = struct.Struct(self._endian + "IIII")
            (self._linktype,) = struct.unpack(self._endian + "I", self._buf[20:24])
            self._write(bytes(self._buf[:24]))
            del self._buf[:24]
            self._header_done = True

        while len(self._buf) >= 16:
            ts_sec, ts_usec, incl_len, orig_len = self._rec.unpack(self._buf[:16])
            if incl_len > MAX_CAPTURE_RECORD:
                raise RuntimeError(
                    f"Cannot redact: implausible packet length ({incl_len} bytes); "
                    "stream is corrupt or out of sync."
                )
            if len(self._buf) < 16 + incl_len:
                return  # wait for the rest of this packet
            frame = bytes(self._buf[16:16 + incl_len])
            del self._buf[:16 + incl_len]
            kept = self._redact(frame)
            self._write(self._rec.pack(ts_sec, ts_usec, len(kept), orig_len))
            self._write(kept)

    def _redact(self, frame):
        """Return the leading header bytes of ``frame`` to keep (payload dropped)."""
        if self._linktype != 1:  # only LINKTYPE_ETHERNET is parsed
            return frame[:54]    # conservative fixed prefix (Eth+IPv4+TCP sized)
        n = len(frame)
        if n < 14:
            return frame
        etype = int.from_bytes(frame[12:14], "big")
        off = 14
        # Walk one or more VLAN tags (802.1Q / QinQ).
        while etype in (0x8100, 0x88A8, 0x9100) and n >= off + 4:
            etype = int.from_bytes(frame[off + 2:off + 4], "big")
            off += 4
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


def open_target(to):
    """Return (write_fn, close_fn, proc) depending on the target."""
    # Isolate subprocess environment: only pass necessary PATH and TERM
    clean_env = {"PATH": os.environ.get("PATH", ""), "TERM": os.environ.get("TERM", "dumb")}

    if to == "wireshark":
        wireshark = shutil.which("wireshark")
        if not wireshark:
            raise RuntimeError("wireshark not found in PATH.")
        proc = subprocess.Popen([wireshark, "-k", "-i", "-"], 
                                stdin=subprocess.PIPE, env=clean_env)
        return proc.stdin.write, proc.stdin.close, proc
    if to == "ntopng":
        ntopng = shutil.which("ntopng")
        if not ntopng:
            raise RuntimeError("ntopng not found in PATH.")
        proc = subprocess.Popen([ntopng, "-i", "-"], 
                                stdin=subprocess.PIPE, env=clean_env)
        return proc.stdin.write, proc.stdin.close, proc
    if to in ("-", "stdout"):
        return sys.stdout.buffer.write, lambda: None, None
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(safe_capture_path(to), flags, 0o600)
    f = os.fdopen(fd, "wb")
    return f.write, f.close, None

def main():
    dotenv = load_dotenv()

    def cfg(name, default=None):
        return os.environ.get(name, dotenv.get(name, default))

    def cfg_bool(name, default=False):
        val = cfg(name)
        if val is None:
            return default
        return val.lower() in ("1", "true", "yes")

    ap = argparse.ArgumentParser(description="Live capture from a FRITZ!Box")
    ap.add_argument("--host", default=cfg("FRITZ_HOST", DEFAULT_HOST),
                    help="box host/IP (default from .env / fritz.box)")
    ap.add_argument("--https", action="store_true",
                    default=cfg_bool("FRITZ_HTTPS"),
                    help="use HTTPS instead of HTTP (or FRITZ_HTTPS=true in .env)")
    ap.add_argument("--https-insecure", action="store_true",
                    default=cfg_bool("FRITZ_HTTPS_INSECURE"),
                    help="disable HTTPS certificate verification (unsafe; prefer --cacert)")
    ap.add_argument("--cacert", default=cfg("FRITZ_CACERT"),
                    help="PEM file to verify the box's HTTPS cert against "
                         "(pin a self-signed cert); or FRITZ_CACERT in .env")
    ap.add_argument("--user", default=cfg("FRITZ_USER"),
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
                    default=cfg_bool("FRITZ_REDACT"),
                    help="strip packet payloads, keep only headers (who/where/"
                         "size, not content); or FRITZ_REDACT=true in .env")
    args = ap.parse_args()

    if not args.user:
        sys.exit("No user. Set FRITZ_USER in .env or use --user.")

    try:
        validate_host(args.host)
        validate_capture_args(args)
    except ValueError as exc:
        sys.exit(f"ERROR: {exc}")

    scheme = "https" if args.https else "http"
    base = f"{scheme}://{args.host}"
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
    if args.password_file:
        try:
            password = read_password_file(args.password_file)
        except ValueError as exc:
            sys.exit(f"ERROR: {exc}")
    else:
        password = cfg("FRITZ_PW") or getpass.getpass("FRITZ!Box password: ")
    opener = build_opener(scheme, args.https_insecure, args.cacert)

    challenge, blocktime = get_challenge(opener, base)
    if blocktime:
        print(f"Note: box reports BlockTime {blocktime}s (too many failed logins).",
              file=sys.stderr)
    sid = get_sid(opener, base, args.user, solve_challenge(challenge, password))
    print("Login ok.", file=sys.stderr)

    if args.list:
        list_interfaces(opener, base, sid)
        return

    if not args.iface:
        sys.exit("Please provide --iface (or run --list first).")

    q = urllib.parse.urlencode({
        "ifaceorminor": args.iface, "snaplen": args.snaplen,
        "filter": args.filter, "capture": "Start", "sid": sid,
    })
    cap_url = f"{base}/cgi-bin/capture_notimeout?{q}"
    stop_url = f"{base}/cgi-bin/capture_notimeout?capture=Stop&sid={sid}&ifaceorminor={args.iface}"

    write, close, proc = open_target(args.to)
    if args.redact:
        write = PcapRedactor(write).feed
        print("[*] Redaction ON: payloads stripped; only packet headers "
              "(addresses, ports, sizes) are recorded.", file=sys.stderr)
    shutdown_requested = False
    capture_error = None

    def signal_handler(*_):
        nonlocal shutdown_requested
        shutdown_requested = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Capture running on {args.iface} -> {args.to}. Stop with Ctrl-C.",
          file=sys.stderr)
    try:
        resp = http_get(opener, cap_url, binary=True, timeout=None)
        while not shutdown_requested:
            chunk = resp.read(65536)
            if not chunk:
                break
            write(chunk)
            if args.to in ("-", "stdout"):
                sys.stdout.buffer.flush()
    except BrokenPipeError:
        pass
    except Exception as exc:  # noqa: BLE001
        capture_error = exc
        msg = re.sub(r"sid=[0-9a-f]{16,64}", "sid=***HIDDEN***", str(exc))
        print(f"\nERROR: {msg}", file=sys.stderr)
    finally:
        if not shutdown_requested:
            print("\n[*] Stopping capture...", file=sys.stderr)
        try:
            http_get(opener, stop_url, binary=True, timeout=5).read(1024)
        except Exception:  # noqa: BLE001
            pass
        try:
            close()
        except Exception:  # noqa: BLE001
            pass
        if proc:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass
    if capture_error:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, urllib.error.URLError, ssl.SSLError) as exc:
        sys.exit(f"ERROR: {exc}")
