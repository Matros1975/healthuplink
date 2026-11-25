# Health Uplink

Your full Apple Health history on a server you control, kept current in the background. One command installs the free, open-source receiver; pairing is a QR scan.

Health Uplink has two parts. The iPhone app reads your Apple Health data and sends it to a receiver you run yourself: on a home server, a NAS or a small cloud machine. AI agents then read your data from the receiver through MCP, for example Claude Code. The iPhone app is coming to the App Store. <!-- App Store link: added after approval. --> This repository holds the receiver, the data contract both sides follow, and the Swift code the app uses to encrypt and sign what it sends.

Works with Apple Health. Not a medical device.

- `receiver/`: the receiver (Python). It stores what your phone sends in SQLite and serves read-only MCP tools at `/mcp`.
- `contract/`: the data contract (`SPEC.md`) and the test vectors every receiver must pass.
- `swift/HealthUplinkSeal/`: the Swift package the iPhone app uses to seal, sign and encode batches, so the encryption code that ships in the app can be read and tested.
- `docs/`: the website, including the security write-up (`docs/security.html`).

## How it works

```
iPhone app ─push─▶ outbox ─▶ upload ─▶ receiver (Docker, always on) ─▶ SQLite store ◀─ MCP /mcp ◀── agents
```

The phone only sends; it never serves anything. It reads new Apple Health data in the background (iOS keeps Apple Health closed while the phone is locked, so records from that time follow after the next unlock), packs it into batches, encrypts each batch to the receiver's key and signs it, keeps the batches in an outbox and uploads them in order. The receiver checks and decrypts each batch and writes it into a SQLite store on its own disk. Agents query that store through MCP, so a locked phone, or a phone with no signal, never blocks a question. Every MCP answer says when the last upload arrived and how old each source's newest sample is, so an agent can tell current data from old data.

What gets sent:

- daily values (steps, energy, resting heart rate and so on) for your whole history;
- sleep nights for the last 365 days on the first sync; "Resend from date" in the app sends older nights too;
- detailed records (each heart rate reading, each weight entry and so on) for the last 365 days.

Workouts, ECG recordings, State of Mind and workout routes are not sent yet.

When you delete a single record in Apple Health, the deletion reaches your receiver too. Daily values for the last 30 days are recalculated on the phone and sent again, but a day whose records were all deleted keeps its old value on the receiver for now.

## Quick start A: Tailscale (recommended)

[Tailscale](https://tailscale.com) puts the server and the iPhone on one private network (a tailnet) that WireGuard encrypts. The receiver can then use plain `http://`, and it works away from home too.

1. Install Tailscale on the server and on the iPhone, and log in to the same account on both.
2. Find the server's tailnet IP address with `tailscale ip -4` (it starts with `100.`). Use this IP address and not the `*.ts.net` name: the iPhone app cannot resolve `*.ts.net` names.
3. Get the compose file and the settings template, then create `.env`:

   ```sh
   git clone https://github.com/Matros1975/healthuplink.git
   cd healthuplink
   cp .env.example .env
   ```

   In `.env`, set (with your own IP address and time zone):

   ```sh
   HU_PUBLISH_ADDR=100.100.1.1
   HU_PUBLIC_URL=http://100.100.1.1:8796
   HU_TLS=off
   HU_TZ=Europe/Berlin
   ```

4. Start the receiver and print a pairing code:

   ```sh
   docker compose up -d
   docker compose exec healthuplink healthuplink pair
   ```

5. In the iPhone app, tap Pair and scan the QR code from the terminal. The code works once and expires after 10 minutes; run `pair` again for a new one.

Docker publishes port 8796 only on the address in `HU_PUBLISH_ADDR`, so the receiver is not reachable from your LAN or the internet. Tailscale must be up before the container starts, because Docker cannot publish on an address the machine does not have yet.

## Quick start B: home network with TLS

Without Tailscale, the phone talks to the receiver over HTTPS on your home network. The receiver makes its own certificate, and the QR code carries the certificate's fingerprint (a pin), so the phone talks only to this receiver and nothing on the network can step in between. That holds as long as the screen showing the QR code is your own; see [what the encryption does not protect](https://healthuplink.front-side-solutions.com/security.html#qr-screen).

In `.env`, use the server's LAN IP address (give it a fixed address in your router) or its `.local` name:

```sh
HU_PUBLISH_ADDR=192.168.1.10
HU_PUBLIC_URL=https://192.168.1.10:8796
HU_TLS=self-signed
HU_TZ=Europe/Berlin
```

Then start and pair as in quick start A:

```sh
docker compose up -d
docker compose exec healthuplink healthuplink pair
```

When you pair, the app asks for Local Network access; allow it. With `HU_TLS=self-signed` the pairing code always carries the pin; `HU_TLS_PIN` has no effect there. `docker compose exec healthuplink healthuplink tls show` prints the pin and where the certificate is stored.

The certificate's key is created once and stays in the Docker volume, so the pin stays the same when you change `HU_PUBLIC_URL`. If the volume is lost, the receiver gets a new key, and the app reports "Another device answered at …" and keeps your data queued until you scan a new code.

A self-signed certificate works only when the phone reaches the receiver by an IP address or a `.local` name, because iOS does not let an app replace normal certificate checks for an internet domain name. A receiver behind an internet name such as `health.example.com` needs a certificate from a public certificate authority (for example Let's Encrypt). You have two ways:

- Let the receiver serve it: `HU_TLS=files`, `HU_TLS_PIN=false`, `HU_TLS_CERT=/tls/cert.pem` and `HU_TLS_KEY=/tls/key.pem`, and uncomment the `./tls:/tls:ro` volume in `compose.yaml`. The files must be readable by user ID 1000 inside the container.
- Put a reverse proxy that holds the certificate in front of the receiver, and keep `HU_TLS=off` on the receiver.

`pair` refuses a self-signed certificate with an internet name and tells you which of these to use.

## Quick start C: without Docker

The receiver is a Python package (Python 3.12 or newer):

```sh
pipx install healthuplink
export HU_PUBLIC_URL=http://100.100.1.1:8796
export HU_BIND=100.100.1.1:8796
export HU_TZ=Europe/Berlin
healthuplink serve
```

Outside Docker the receiver listens on `127.0.0.1:8796` unless `HU_BIND` says otherwise. Set `HU_BIND` to the tailnet IP address, or, with `HU_TLS=self-signed`, to the LAN IP address. Data goes to `~/.local/share/healthuplink` (or `$XDG_DATA_HOME/healthuplink`) unless `HU_DATA_DIR` names another folder. `serve` refuses an `HU_PUBLIC_URL` the phone would not accept, for example plain `http://` to a LAN address, and says why.

Pair from a second terminal with the same settings: `healthuplink pair`.

To keep it running, put the settings in `~/.config/healthuplink/env` (one `NAME=value` per line, without `export`) and add a `systemd --user` unit, `~/.config/systemd/user/healthuplink.service`:

```ini
[Unit]
Description=Health Uplink receiver
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=%h/.config/healthuplink/env
ExecStart=%h/.local/bin/healthuplink serve
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now healthuplink
loginctl enable-linger "$USER"   # keep it running when you are logged out
```

When you run other `healthuplink` commands by hand, load the same file first so they use the same data folder: `set -a; . ~/.config/healthuplink/env; set +a`.

## Connect an agent

Create a token for each agent. The token is printed once; copy it.

```sh
docker compose exec healthuplink healthuplink tokens create --name claude-code
```

(Without Docker: `healthuplink tokens create --name claude-code`.) Then add the receiver to Claude Code:

```sh
claude mcp add --transport http healthuplink http://100.100.1.1:8796/mcp \
  --header "Authorization: Bearer <token>"
```

Use the same URL as `HU_PUBLIC_URL` with `/mcp` at the end. Add `--scope user` to make it available in every project. Other MCP clients that support streamable HTTP with a bearer token work the same way. `healthuplink tokens list` shows the tokens and `healthuplink tokens revoke claude-code` withdraws one.

With `HU_TLS=self-signed`, Claude Code has to trust the receiver's certificate. Save it to a file and point `NODE_EXTRA_CA_CERTS` at that file in the shell that starts `claude`:

```sh
docker compose exec -T healthuplink healthuplink tls show --pem > healthuplink.pem
export NODE_EXTRA_CA_CERTS="$PWD/healthuplink.pem"
```

(Without Docker: `healthuplink tls show --pem > healthuplink.pem`.)

The MCP tools are read-only: `list_types`, `list_sources`, `query`, `summary`, `get_sleep` and `sync_status`. Text that came from your devices (source names, labels) is returned as data, shortened and without control characters.

## Sync notices

The receiver can tell you when syncing stops. It checks every hour and sends at most one notice a day, only while a phone is paired, when:

- no upload has arrived for 18 hours;
- the phone reports batches it could not deliver;
- heart rate or step count had data before and has had nothing new for 48 hours;
- no sleep night has arrived for 60 hours.

A notice holds hours, counts and type names, never health values.

Notices go to a webhook of your choice. Set in `.env`:

```sh
HU_NOTIFY_WEBHOOK_URL=https://hooks.example.com/healthuplink
HU_NOTIFY_FORMAT=json
```

The receiver sends a `POST` with this body:

```json
{
  "source": "healthuplink",
  "kinds": ["stale"],
  "text": "No upload from Health Uplink for 19 hours. Open Health Uplink on your iPhone.",
  "at": "2026-11-24T09:00:00Z"
}
```

`kinds` holds one or more of `stale`, `dead_letters`, `type_quiet` and `sleep_quiet`. Only `http://` and `https://` URLs are accepted. The receiver does not follow redirects: a `3xx` answer counts as a failure, and a failed notice is tried again an hour later.

For push notifications on your phone, a self-hosted [ntfy](https://ntfy.sh) server works with the plain-text format; the notice title is "Health Uplink":

```sh
HU_NOTIFY_WEBHOOK_URL=https://ntfy.example.com/healthuplink
HU_NOTIFY_FORMAT=text
```

Telegram is another option: set `HU_TELEGRAM_TOKEN` to your bot's token and `HU_TELEGRAM_CHAT_ID` to your chat ID. When both a webhook and Telegram are set, the receiver sends to both.

After changing `.env`, apply it with `docker compose up -d`.

## Settings

All settings are environment variables. With Docker they go in `.env`.

| Variable | Default | Meaning |
|---|---|---|
| `HU_PUBLISH_ADDR` | none (required) | Docker only: the address on the host that Docker publishes port 8796 on. Use the tailnet or LAN IP address, not `0.0.0.0`. |
| `HU_PUBLIC_URL` | empty | The address the phone uses, put into the pairing code. `pair` needs it. Plain `http://` only for a tailnet IP address (`100.64.0.0/10`); every other address needs `https://`. |
| `HU_BIND` | `127.0.0.1:8796` (`0.0.0.0:8796` in the image) | Address and port the server listens on. In Docker, leave it and use `HU_PUBLISH_ADDR`. |
| `HU_DATA_DIR` | `~/.local/share/healthuplink` (`/data` in the image) | Store, backups, keys and certificate. |
| `HU_TLS` | `off` | `off`, `self-signed` (the receiver makes a certificate and the pairing code carries its pin) or `files` (your own certificate). |
| `HU_TLS_CERT`, `HU_TLS_KEY` | empty | With `HU_TLS=files`: paths to the certificate chain and the private key (PEM). |
| `HU_TLS_PIN` | `true` | Only for `HU_TLS=files` (with `self-signed` the pairing code always carries the pin): `false` for a certificate from a public certificate authority, so the pairing code carries no pin. A pinned certificate must have an ECDSA P-256 key. |
| `HU_TZ` | `UTC` | Your home time zone (IANA name such as `Europe/Berlin`), for the nightly backup and clean-up. |
| `HU_NOTIFY_WEBHOOK_URL` | empty | Where sync notices go (`http://` or `https://`); empty for none. |
| `HU_NOTIFY_FORMAT` | `json` | `json`, or `text` for ntfy and similar services. |
| `HU_TELEGRAM_TOKEN`, `HU_TELEGRAM_CHAT_ID` | empty | Optional: send sync notices to Telegram as well. |
| `HU_EXTENSIONS` | empty | Comma-separated Python modules with a `register(ctx)` function, loaded at start (see `receiver/src/healthuplink/extensions.py`). |
| `HU_UNITS_FILE`, `HU_CUMULATIVE_FILE` | empty | For development: replace the unit table or the list of cumulative types that ship with the receiver. |

## Data, backups and deleting

Everything the receiver keeps is in its data folder; with Docker that is the `healthuplink-data` volume:

- `store.db`: your health data, the paired devices, hashes of the MCP tokens, and a record of each batch (kept 400 days);
- `backups/`: a copy of the store made every night after 03:30 in `HU_TZ`; the newest 14 are kept;
- `keys/`: the receiver's encryption keys;
- `tls/`: the self-signed certificate and its key, with `HU_TLS=self-signed`.

The backups sit on the same disk as the store. Copy them somewhere else if that disk matters to you:

```sh
docker compose exec healthuplink healthuplink backup   # make one now; prints its path
docker compose cp healthuplink:/data/backups ./healthuplink-backups
```

To stop a phone from sending, unpair it in the app, or revoke it on the receiver (data already received stays):

```sh
docker compose exec healthuplink healthuplink devices list
docker compose exec healthuplink healthuplink devices revoke <device_id>
```

`healthuplink keys rotate` gives the receiver a new encryption key. The old key is kept for 30 days so batches already queued on the phone still arrive, and the phone uses the new key after you pair it again.

To delete everything, remove the container and its volume: `docker compose down -v`. That deletes the store, the backups, the keys and the certificate. Without Docker, delete the data folder (`~/.local/share/healthuplink` or your `HU_DATA_DIR`). Backups you copied elsewhere stay where you put them; delete those yourself. Frontside runs no server and receives none of your data, so there is nothing to delete on our side.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability, and the [security write-up](https://healthuplink.front-side-solutions.com/security.html) (also in `docs/security.html`) for what the encryption protects and what it does not.

## Licence

Apache License 2.0; see `LICENSE` and `NOTICE`. © 2026 Frontside Solutions B.V.
