# FritzDump

Live packet capture from a FRITZ!Box.

FritzDump logs in to the hidden packet-capture page of a FRITZ!Box and streams
the live traffic of an interface (LAN, Wi-Fi, or WAN) straight into Wireshark,
ntopng, a `.pcap` file, or stdout — so you can watch and analyze the live
connections of your own network in real time. No need to click through the
web UI: it handles the login and starts the capture for you.

Supports both the old MD5 login and the current PBKDF2 login
(FRITZ!OS 7.24+ / 8.x).

Author: arn-c0de · License: MIT

## How it works

1. Authenticates against `login_sid.lua` (MD5 or PBKDF2 challenge/response).
2. Opens the box's internal `capture_notimeout` endpoint for the chosen
   interface.
3. Pipes the raw pcap stream live to your chosen target.

## Setup

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` with your FRITZ!Box login:

```bash
FRITZ_HOST=192.168.178.1
FRITZ_USER=fritz-capture-user
FRITZ_PW=your-password
FRITZ_HTTPS=true
# Pin the box's self-signed cert so HTTPS is verified (recommended):
# FRITZ_CACERT=fritzbox.pem
```

Tip: create a dedicated FRITZ!Box user that only has the
**"FRITZ!Box settings"** permission. For password-only login (no user name),
set `FRITZ_USER=dslf-config`.

## Usage

Check login and list the available interface IDs:

```bash
./run.sh test
```

Capture the default set (LAN + Wi-Fi 5 GHz + Wi-Fi 2.4 GHz) into `./dumps/`:

```bash
./run.sh
```

Stop with `Ctrl-C`.

### Other modes

```bash
./run.sh file 1-lan         # write one interface to a .pcap file
./run.sh wireshark 1-lan    # stream live into Wireshark
./run.sh ntopng 1-lan       # stream live into ntopng
./run.sh raw 1-lan          # raw pcap to stdout (pipe into your own tool)
```

You can also call the Python tool directly:

```bash
./fritzdump.py --list                         # list interfaces
./fritzdump.py --iface 2-1 --to wireshark     # WAN live into Wireshark
./fritzdump.py --iface 1-0 --to capture.pcap  # write to a file
./fritzdump.py --iface 2-1 --to - | your-tool # raw pcap to stdout
./fritzdump.py --iface 2-1 --filter 'host 1.2.3.4'   # pcap filter
./fritzdump.py --iface 2-1 --to cap.pcap --redact    # headers only, no payload
```

### Redacted capture (metadata only)

Pass `--redact` (or set `FRITZ_REDACT=true` in `.env`) to record traffic
**without storing packet contents**. Each frame is truncated to its L2–L4
headers: Ethernet (MAC addresses), IPv4/IPv6 (IP addresses, protocol) and
TCP/UDP/ICMP (ports, flags) are kept, the application payload is dropped. The
original frame length is preserved in the record, so you still see **how long**
a message was and **between whom** it flowed — just not what was inside.

The output is still a valid pcap and opens normally in Wireshark/ntopng (it
shows `[Packet size limited during capture]` for the stripped payloads). Works
for every target (`--to wireshark | ntopng | file | -`).

```bash
./run.sh file 1-lan     # full capture (default)
FRITZ_REDACT=true ./run.sh file 1-lan   # redacted: headers only
```

Interface IDs depend on your model/firmware — run `./run.sh test` to find them.
The defaults below are what a FRITZ!Box 6591 reports:

- LAN bridge: `1-lan`
- Wi-Fi 5 GHz: `4-133`
- Wi-Fi 2.4 GHz: `4-135`
- WAN (example): `2-1`

## Dumps

Captures are written to `./dumps/`. When a new default capture starts, old
`dump_*` folders are removed first. The `dumps/` folder and all `*.pcap`,
`*.pcapng`, and `*.eth` files are git-ignored.

## Security notes

- Only capture traffic on networks you own or are explicitly authorized to inspect.
- Never commit `.env` or any packet dumps.
- **Use HTTPS.** Plain HTTP sends the session token and every captured packet
  across your LAN/Wi-Fi in clear text; the tool prints a warning when you do.
- The FRITZ!Box uses a self-signed certificate. Rather than disabling
  verification, **pin it** so HTTPS stays authenticated and MITM-resistant:

  ```bash
  openssl s_client -connect 192.168.178.1:443 -showcerts </dev/null \
    2>/dev/null | openssl x509 > fritzbox.pem
  ./fritzdump.py --https --cacert fritzbox.pem --list   # or FRITZ_CACERT in .env
  ```

- `--https-insecure` is a last resort: it leaves the link encrypted but
  unauthenticated, so anyone on your network can impersonate the box. The tool
  warns loudly and refuses to combine it with `--cacert`.
- Capture filters (`--filter`) are restricted to a BPF character whitelist.
- Pcap dumps contain your real traffic (including credentials from any
  unencrypted sites). They are written `chmod 600` under `./dumps/` and are
  git-ignored — delete them when you're done analyzing. If you only need
  traffic metadata (who talks to whom, message sizes), use `--redact` /
  `FRITZ_REDACT=true` so payloads are never written to disk.
