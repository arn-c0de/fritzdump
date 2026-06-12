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
# The login API answers only on the box's LAN IP, whose self-signed cert has no
# IP SAN -> verification can't pass there, so on a trusted LAN use:
# FRITZ_HTTPS_INSECURE=true   (encrypted, not authenticated; see Security below)
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

If you'd rather not keep the password in `.env`, pass `--password-file
<path>` to read it from a local file instead (the file must be a regular,
non-symlink file that is not readable by group/others). When neither `.env`
nor `--password-file` provides a password, the tool prompts for it.

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
- Wi-Fi 2.4 GHz: `1-ath0`
- WAN (example): `2-1`

For 2.4 GHz, `./run.sh home` captures the **raw radio** `1-ath0`, not the
logical AP `4-135`: on this firmware `4-135` accepts the capture but streams
zero packets, so 2.4 GHz-only devices would be silently missed. Override the
whole set with `FRITZ_HOME_IFACES="lan:1-lan wifi_5ghz:4-133 wifi_24ghz:1-ath0"`.

## Dumps

Captures are written to `./dumps/`. When a new default capture starts, old
`dump_*` folders are removed first. The `dumps/` folder and all `*.pcap`,
`*.pcapng`, and `*.eth` files are git-ignored.

## Development

The login challenge math, input validation, interface parsing and the pcap
redactor are covered by unit tests (standard library only, no box needed):

```bash
python3 -m unittest discover -s tests
```

## Security notes

- Only capture traffic on networks you own or are explicitly authorized to inspect.
- Never commit `.env` or any packet dumps.
- **Use HTTPS.** Plain HTTP sends the session token and every captured packet
  across your LAN/Wi-Fi in clear text; the tool prints a warning when you do.
- **TLS verification, first-run gotcha.** The login API (`login_sid.lua`)
  answers only on the box's **LAN IPv4** — the `fritz.box` hostname
  (IPv6/MyFRITZ) returns no login challenge. On that LAN IP the box presents a
  **self-signed certificate with no IP SAN**, so HTTPS verification + hostname
  check can never pass and `--cacert` does **not** help (the hostname check
  still fails on a bare IP). With `--https` and verification on you therefore
  get `CERTIFICATE_VERIFY_FAILED` and the capture won't start. Your options:

  - **Trusted wired LAN (usual choice):** `--https-insecure` (or
    `FRITZ_HTTPS_INSECURE=true`). The link stays **encrypted** (credentials and
    packets are never in clear text) but is **not authenticated**, so an active
    MITM on the LAN could impersonate the box. Still strictly better than plain
    HTTP. The tool warns loudly and refuses to combine it with `--cacert`.
  - **Pin + verify** only works if you reach the box by a hostname that **is in
    the cert SAN** (e.g. `fritz.box`) *and* resolves to it on the LAN; then set
    that name as `FRITZ_HOST`, point `--cacert`/`FRITZ_CACERT` at the box PEM,
    and keep verification on. Note the box may serve a publicly-trusted
    (Let's Encrypt) cert on its hostname, in which case no pinning is needed —
    but that cert rotates, so don't pin its leaf.

  ```bash
  # export the cert presented on the LAN IP (for the pin+verify case):
  openssl s_client -connect 192.168.178.1:443 -showcerts </dev/null \
    2>/dev/null | openssl x509 > fritzbox.pem
  ```
- Capture filters (`--filter`) are restricted to a BPF character whitelist.
- The current PBKDF2 login is always used when the box offers it. The old
  pre-7.24 **MD5 login is weak and is refused by default** to stop a forced
  downgrade; enable it only for genuinely old firmware with
  `--allow-legacy-login` / `FRITZ_ALLOW_LEGACY=true`, ideally over HTTPS.
- Pcap dumps contain your real traffic (including credentials from any
  unencrypted sites). They are written `chmod 600` under `./dumps/` and are
  git-ignored — delete them when you're done analyzing. If you only need
  traffic metadata (who talks to whom, message sizes), use `--redact` /
  `FRITZ_REDACT=true` so payloads are never written to disk.
