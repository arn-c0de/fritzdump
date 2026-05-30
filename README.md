# FritzDump

Simple FRITZ!Box packet capture helper.

It logs in to the FRITZ!Box capture page and writes PCAP dumps for LAN,
Wi-Fi 5 GHz, and Wi-Fi 2.4 GHz.

Author: arn-c0de

License: MIT

## Setup

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set your FRITZ!Box login:

```bash
FRITZ_HOST=192.168.178.1
FRITZ_USER=fritz-capture-user
FRITZ_PW=your-password
```

Use a dedicated FRITZ!Box user with only the needed permissions.

## Usage

List available interfaces:

```bash
./run.sh test
```

Start the default capture:

```bash
./run.sh
```

Default captures:

- LAN: `1-lan`
- Wi-Fi 5 GHz: `4-133`
- Wi-Fi 2.4 GHz: `4-135`

Stop with `Ctrl-C`.

## Dumps

Dumps are written to:

```text
./dumps/
```

Old dump folders are deleted when a new default capture starts.

The `dumps/` folder and all `*.pcap`, `*.pcapng`, and `*.eth` files are ignored by Git.

## Other Modes

```bash
./run.sh file 1-lan
./run.sh wireshark 1-lan
./run.sh ntopng 1-lan
./run.sh raw 1-lan
```

## Security Notes

- Do not commit `.env`.
- Do not commit packet dumps.
- Capture only networks you own or are allowed to inspect.
- HTTPS certificate verification is enabled by default when HTTPS is used.
