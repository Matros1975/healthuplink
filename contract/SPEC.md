# Health Uplink: data contract

Version 1 (envelope 1, body 1, tools 1). This is the contract between the Health Uplink iPhone app and a receiver: pairing, the encrypted batch envelope, the body, the receiver's store and the MCP tools. Any receiver that implements it must pass the shared vectors in `contract/vectors/`. Section 4 (a pairing mode dropped before release) is not part of this copy, so the numbering skips it.

## 1. Parties and flow

```
iPhone app ─push batch─▶ Receiver ─▶ store ◀─pull─ MCP ◀── agent
```

- The phone pushes whenever iOS lets it run. It never serves requests.
- Agents pull from the receiver's store through MCP. A locked phone never blocks a query, and every answer says how old the data is.
- The phone posts directly to the user's receiver. `"direct"` is the only pairing mode.
- The contract does not depend on which receiver runs it. Today one implements it: the Docker receiver (`receiver/`, open source, always on). A receiver in a Mac app may come later. Every receiver must pass `contract/vectors/v1.json`. Where this file names the Docker CLI or the host address for pairing and `/v1/*`, another receiver does the same thing in its own way, under the same transport rule (section 2).
- Parts marked "App Store milestone; v0 receivers and apps ignore it" are additive: a v0 app does not send them, and a v0 receiver ignores them as unknown fields.
- An earlier draft had a second pairing mode, `"mailbox"`. It was dropped before release; apps reject it as an unsupported mode.

Three parts are versioned independently: the envelope (`envelope_version`), the body (`body_version`) and the MCP tool set (`tools_version`). Every reader ignores fields it does not know.

Encoding rules for the whole contract: base64 is standard with padding (RFC 4648 §4); UUIDs are lowercase; timestamps are UTC ISO 8601 with `Z`, whole seconds, no fraction (`2026-11-22T07:30:12Z`); `lp(x)` means a 4-byte big-endian length followed by the UTF-8 or raw bytes of `x`.

Clarifications:

1. Inside `lp(...)`, `proof`, `confirm` and `info`, keys and tokens are their raw decoded bytes (`pair_token` 16 bytes, `device_signing_pk`, `server_pk`, `enc` 32 bytes each). IDs and timestamps are their UTF-8 strings exactly as sent.
2. `GET /v1/status` carries the headers `X-HU-Device`, `X-HU-At` and `X-HU-Sig`. The signature covers `"HUv1-status" || lp(device_id) || lp(at)`. Unpair and status reject an `at` more than 10 minutes from receiver time.
3. `seq` starts at 1 per device.
4. A decompressed body over 16 MiB or more than 10,000 items answers 413 `too_large`. Other validation failures answer 422 `invalid_body`.

## 2. Pairing (direct mode)

1. The user runs `docker exec healthuplink healthuplink pair` on the receiver's host. The CLI prints a QR code in the terminal. There is no web page for pairing.
2. QR payload:

```json
{
  "v": 1,
  "mode": "direct",
  "url": "http://100.100.1.1:8796",
  "server_pk": "<base64 X25519 public key>",
  "key_epoch": 1,
  "pair_token": "<base64, 128 bits, single use, 10 min TTL>"
}
```

URL rules: plain `http://` is accepted only for tailnet addresses: IPv4 literals in `100.64.0.0/10` (Tailscale's CGNAT range), written as four decimal octets without leading zeros. WireGuard encrypts and authenticates that link. Every other host needs `https://`, either with a certificate valid under the system's trust store or pinned through `tls_sha256`. `*.ts.net` names are rejected because the iPhone cannot resolve them. This holds in v0 too.

`tls_sha256`: any receiver may send it; a v0 app ignores it. The value is the standard base64 (with padding) of SHA-256 over the DER `SubjectPublicKeyInfo` of the receiver certificate's public key. Receivers generate ECDSA P-256 keys only, and the phone pins P-256 keys only: any other key type under a pin counts as a pin mismatch. The payload stays `"v": 1` because the field is additive (section 1). A v0 app that ignores it and meets a self-signed certificate fails the TLS handshake before it sends `pair_token`, so the token is never exposed.

When the field is present the phone pins it for every request to that receiver (pair, batches, status, unpair, healthz): it sends `pair_token` only over a TLS connection whose key matches, and it never falls back to system trust or to plain HTTP. The phone rejects the payload when:

- `tls_sha256` is present but malformed: not a string, not base64, or not 32 bytes (`bad_pin`);
- `tls_sha256` comes with an `http://` URL, tailnet included (`needs_https`);
- `tls_sha256` comes with a host that is not an IPv4 literal, a `.local` name or an unqualified name (no dot) (`pin_needs_local_host`). iOS does not let an app loosen server trust for other names ("You cannot loosen server trust requirements for an ATS-protected domain", Apple, Performing manual server trust authentication), so a receiver behind a public DNS name needs a CA-valid certificate and no pin. An IPv6 literal with a pin is refused the same way in v1.

A pin mismatch is a transient result (section 3) with the Status line "Another device answered at <host>". The app never pairs again on its own. Status offers "Pair again with this receiver", which requires a fresh scan or paste of the receiver's QR payload (with its new pin) and a confirmation. The Docker receiver on a tailnet may stay on plain HTTP without the field, since WireGuard already encrypts and authenticates the link.

Shared vectors: `contract/vectors/tls-v1.json` holds a fixed P-256 certificate, its key and its `tls_sha256`; `contract/vectors/pairing-v1.json` lists payloads with the expected result (`ok`, `bad_payload`, `unsupported_version`, `unsupported_mode`, `tailnet_name`, `needs_https`, `bad_pin`, `pin_needs_local_host`). Each case repeats the payload's raw `url` and `tls_sha256`, so a URL-only check can use the same cases. Both receivers and the app test against them.

3. The app creates an Ed25519 device signing key in the Keychain (`ThisDeviceOnly`, no iCloud Keychain sync) and calls `POST /v1/pair`. Pairing is the only place where a key is created:

```json
{
  "pair_token": "...",
  "device_signing_pk": "<base64 Ed25519>",
  "device_name": "My iPhone",
  "proof": "<base64 Ed25519 sig over 'HUv1-pair' || lp(pair_token) || lp(device_signing_pk)>"
}
```

4. Response `200`:

```json
{ "device_id": "<uuid>", "confirm": "<base64 HMAC-SHA256(key=pair_token, msg=device_signing_pk || server_pk)>" }
```

The app checks `confirm` before it trusts the receiver. `/v1/pair` allows 5 attempts per minute. After a successful pairing the app saves the home time zone (section 5, "Types and units") with the pairing.

Unpair and revoke:

- The app calls `POST /v1/unpair` with `{device_id, at, sig}`, where `sig` covers `'HUv1-unpair' || lp(device_id) || lp(at)`. Then it deletes its keys, anchors and outbox.
- On the host, `healthuplink devices revoke <device_id>` handles a lost phone.

Server key rotation: `healthuplink keys rotate` creates a new key with `key_epoch + 1`. The receiver keeps old keys for 30 days so a queued outbox still decrypts. The phone learns the new key only by pairing again.

Pair again: pairing again (or unpairing) deletes the signing key, anchors, outbox and backfill state, then starts a full backfill under the new `device_id`. Batches sealed for the old device are never sent to the new one.

Reinstall: Keychain items survive app deletion on iOS, but anchors and outbox do not. On first launch without a sentinel file the app deletes old Keychain items and starts as a fresh install: new pairing, full backfill. The receiver's UUID keys make the repeated data harmless. Deletes made in Health between the last upload under the old pairing and the new anchors are not sent (see "Backfill and Resend from date").

Protected data: after a reboot and before the first unlock the outbox file and the Keychain item are unreadable. When `UIApplication.isProtectedDataAvailable` is false, the Keychain answers `errSecInteractionNotAllowed`, or SQLite cannot open the outbox, the app releases its held observer handlers and ends the wake window. It creates, deletes and replaces nothing: no new key, no fresh-install wipe, no "Pair again". Reading the key tells "not found" apart from "locked". The fresh-install check runs only while protected data is available. The flag that says the Health permission request was made lives in a small file with no data protection (it holds no health data), so observers are registered correctly before the first unlock, and they are registered again, idempotently, when protected data becomes available.

## 3. Envelope (`envelope_version` 1)

`POST /v1/batches`:

```json
{
  "envelope_version": 1,
  "batch_id": "<uuidv7>",
  "device_id": "<uuid>",
  "key_epoch": 1,
  "seq": 1842,
  "created_at": "2026-11-22T07:30:12Z",
  "enc": "<base64 HPKE encapsulated key>",
  "ciphertext": "<base64>",
  "sig": "<base64>"
}
```

Crypto, all from CryptoKit on iOS 17:

- HPKE base mode, suite `DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305`, a fresh sender (`HPKE.Sender`) per batch.
- `info` = `"healthuplink/v1" || lp(device_id) || server_pk`
- `aad` = `lp(batch_id) || lp(device_id) || u32(key_epoch) || u64(seq) || lp(created_at)`
- Plaintext = gzip of the body JSON.
- `sig` = Ed25519 by the device key over `"HUv1-batch" || aad || lp(enc) || SHA-256(ciphertext)`.

Binding the envelope fields into both `aad` and `sig` means a captured ciphertext cannot be re-posted under another `batch_id`, `seq` or device.

Limits: ciphertext at most 1 MiB, HTTP body at most 1.5 MiB, decompressed body at most 16 MiB, at most 10,000 items per batch. The phone closes a batch at whichever limit it reaches first, item count or ciphertext size.

### Sequence numbers

- `seq` is allocated when a batch enters the outbox and is never reused.
- A sealed batch is never split: the outbox holds only ciphertext, and HPKE base mode gives the sender no way to open it again. The phone prevents 413 by construction (limits above, checked before sealing). `abandoned_seq` stays empty in v0 and is reserved. Item parts (`part`/`parts`) exist only for ECG and routes, which are v1.
- A batch moved to the dead-letter list is reported in `dead_letter_seq`.
- A gap is a `seq` the receiver has not stored and the phone has not reported as abandoned or dead-lettered. `sync_status` shows only real gaps.

### Receiver checks

- Unknown `device_id`, revoked device or bad signature → 401.
- `batch_id` already stored with the same `SHA-256(ciphertext)` → `200 duplicate`. With a different hash → 409.
- Unknown `key_epoch` or failed decryption → 422 `decrypt_failed`.
- Body fails validation → 422 `invalid_body`.
- `envelope_version` or `body_version` not supported → 426 with `{"error": "upgrade_required", "supported": {"envelope": [1], "body": [1]}}`.
- `created_at` more than 1 day in the future or older than 400 days is stored but flagged in `sync_status`.

Every `/v1/*` response is `application/json`. Errors are `{"error": <code>}`; the batch endpoint answers:

| Status | Body |
|---|---|
| 200 | `{"status": "stored"}` or `{"status": "duplicate"}` |
| 400 | `{"error": "bad_request"}` |
| 401 | `{"error": "unauthorized"}` |
| 409 | `{"error": "conflict"}` |
| 413 | `{"error": "too_large"}` (one code everywhere) |
| 422 | `{"error": "decrypt_failed"}` or `{"error": "invalid_body", "reason": "..."}` |
| 426 | `{"error": "upgrade_required", "supported": {...}}` |
| 429 | `{"error": "rate_limited"}` |

The receiver also answers 404 `not_found`, 405 `method_not_allowed` and 500 `internal` in the same shape. The phone does not treat them as verdicts on a batch: a wrong URL or a proxy is likelier than a real verdict.

### App behaviour per response

Responses are not authenticated, so the phone acts on a response only when it is clearly the receiver's. A response counts as a receiver verdict only when its `Content-Type` is `application/json` and its body has one of the shapes in the table above: a `200` with `status` `stored` or `duplicate`, or a 4xx with an `error` from the verdict codes (`bad_request`, `unauthorized`, `conflict`, `decrypt_failed`, `invalid_body`, `too_large`, `rate_limited`, `upgrade_required`) that matches its status as in the table (a 404 with `invalid_body` is not a verdict). Everything else is transient: non-JSON bodies, other shapes, unknown codes, 404 `not_found`, 405 `method_not_allowed`, any 5xx including 500 `internal`, redirects (the phone does not follow them), timeouts and network errors. A transient result keeps the batch queued and applies backoff. The phone never discards or dead-letters a batch on a response it does not recognise.

| Response (receiver verdict) | App action |
|---|---|
| 200 `stored` or `duplicate` | Remove from outbox |
| 401 `unauthorized` | Retry once after an hour; after 3 failures within 24 h pause uploads and show "Pair again" |
| 400 `bad_request`, 409 `conflict`, 422 `invalid_body` | Move to dead-letter list, report `seq`, continue with the next batch (subject to the circuit breaker) |
| 413 `too_large` | Same as the row above. A sealed batch is never split; the phone's limits make this a bug, not a routine case |
| 422 `decrypt_failed` | Keep the batch queued and pause uploads (the receiver key changed or is unknown). Nothing is dead-lettered. The pause is retried on "Sync now" and every 6 hours, like the breaker. Status suggests "Pair again" but does not require it; queued batches are discarded only if the user does pair again, and the full backfill after a re-pair resends their data |
| 426 `upgrade_required` | Pause uploads, show "Update the app or the receiver" |
| 429 `rate_limited`, and every transient result | Exponential backoff from 30 s to 6 h, respect `Retry-After`, at most one retry per background window, check reachability first |

Circuit breaker: at most 3 dead-letters in a row. The third consecutive dead-letter pauses uploads and the Status screen says so in one plain line; queued batches stay queued. Uploads resume on "Sync now" or after 6 hours. After a resume one batch is tried: another dead-letter pauses again at once, a stored batch resets the count. The queue is never emptied by a run of errors.

Backoff reset: "Sync now", the app coming to the foreground and a new usable network path (for example joining Wi-Fi or a VPN coming up) clear the backoff, so a receiver that is back is reached at once instead of after the next scheduled retry.

### Outbox and anchors

- The outbox is a SQLite database in the app container with `completeUntilFirstUserAuthentication` protection, excluded from backup (`isExcludedFromBackup`). It holds sealed envelopes only. The app writes no plaintext health values to files.
- A read and its enqueue are one transaction: the sealed batch and the new HealthKit anchor are saved together. A crash either loses both (the read repeats) or keeps both (the batch is uploaded). Nothing is read twice into the outbox and nothing is lost between read and upload.
- Uploads go strictly in `seq` order, one at a time.
- Dead-letter entries stay on the phone for 30 days, are listed on the Status screen and can be exported for diagnostics (metadata only: `seq`, `batch_id`, `created_at`, size, reason, time, and the first and last day and the types its items covered). The envelope itself is dropped. The covered days tell the user which date to resend from. Their data is recovered with "Resend from date" (section 5) after the cause is fixed.
- Backpressure: when the outbox holds more than 200 MiB or its oldest batch is older than 30 days, the app stops reading new data (anchors stay where they are) and shows why. It never drops queued data.

### Status for the app

`GET /v1/status`, signed as described in clarification 2 of section 1, returns:

```json
{ "high_contiguous_seq": 1834, "last_received_at": "...", "gaps": [1835], "oldest_unacked_at": null, "expired_seq": [] }
```

The example is a device whose batches 1 to 1840 are stored except 1835.

- `high_contiguous_seq` is the highest `seq` such that every `seq` from the pruned floor up to it is stored or reported as abandoned or dead-lettered. The pruned floor is the highest `seq` whose batch record was pruned after 400 days (0 before any prune); pruning never creates gaps.
- `gaps` lists every `seq` above `high_contiguous_seq` and below the highest stored `seq` that is neither stored nor reported, at most 10,000 entries.
- `oldest_unacked_at` and `expired_seq` are always empty (`null` and `[]`). They belonged to mailbox mode, which was replaced; receivers keep sending them and the app ignores them.
- `accepts` (deferred; v0 and v1 receivers do not send it): the item kinds the receiver stores, for example `["samples", "daily", "sleep_nights", "deleted"]`. The phone reads and sends only listed kinds and does not advance anchors for the others, so an older receiver never answers `stored` for data it drops. A receiver without `accepts` is treated as accepting exactly those four v0 kinds, so a later app that sends more kinds stays safe with v1 receivers.

## 5. Body (`body_version` 1)

Plaintext JSON inside the ciphertext. Each array may be absent.

```json
{
  "body_version": 1,
  "app": { "version": "1.0", "build": "12", "os": "26.1", "model": "iPhone16,1", "low_power": false },
  "abandoned_seq": [],
  "dead_letter_seq": [],
  "samples": [
    {
      "uuid": "3f2a...",
      "type": "HKQuantityTypeIdentifierHeartRate",
      "kind": "quantity",
      "start": "2026-11-22T03:12:00Z",
      "end": "2026-11-22T03:12:00Z",
      "value": 52,
      "unit": "count/min",
      "source": { "bundle": "com.apple.health.00000000-0000-4000-8000-0000000000A1", "name": "Apple Watch", "product_type": "Watch7,5" },
      "tz": "Europe/Amsterdam",
      "metadata": { "HKMetadataKeyHeartRateMotionContext": 1 }
    },
    {
      "uuid": "9b10...",
      "type": "HKCategoryTypeIdentifierSleepAnalysis",
      "kind": "category",
      "start": "2026-11-22T01:40:00Z",
      "end": "2026-11-22T02:05:00Z",
      "value": 5,
      "value_label": "asleepREM",
      "source": { "bundle": "com.apple.health.00000000-0000-4000-8000-0000000000A1", "name": "Apple Watch" }
    }
  ],
  "daily": [
    { "type": "HKQuantityTypeIdentifierStepCount", "day": "2026-11-21", "tz": "Europe/Amsterdam", "source": "@merged", "sum": 11234, "n": null, "unit": "count", "partial": false },
    { "type": "HKQuantityTypeIdentifierRestingHeartRate", "day": "2026-11-21", "tz": "Europe/Amsterdam", "source": "com.apple.health.00000000-0000-4000-8000-0000000000A1", "avg": 51, "min": 51, "max": 51, "n": 1, "unit": "count/min", "partial": false }
  ],
  "sleep_nights": [
    {
      "night": "2026-11-22",
      "tz": "Europe/Amsterdam",
      "source": "com.apple.health.00000000-0000-4000-8000-0000000000A1",
      "start": "2026-11-21T22:58:00Z",
      "end": "2026-11-22T05:41:00Z",
      "minutes": { "in_bed": 403, "asleep": 372, "core": 201, "deep": 64, "rem": 89, "unspecified": 18, "awake": 31 },
      "segments": [ { "start": "...", "end": "...", "stage": "core" } ]
    },
    {
      "night": "2026-11-22",
      "tz": "Europe/Amsterdam",
      "source": "@merged",
      "start": "2026-11-21T22:30:00Z",
      "end": "2026-11-22T05:41:00Z",
      "minutes": { "in_bed": 431, "asleep": 381.5 },
      "segments": []
    }
  ],
  "workouts": [
    {
      "uuid": "...",
      "activity": "HKWorkoutActivityTypeRunning",
      "start": "...", "end": "...",
      "source": { "bundle": "...", "name": "..." },
      "stats": {
        "HKQuantityTypeIdentifierActiveEnergyBurned": { "sum": 412, "unit": "kcal" },
        "HKQuantityTypeIdentifierDistanceWalkingRunning": { "sum": 6.2, "unit": "km" },
        "HKQuantityTypeIdentifierHeartRate": { "avg": 148, "max": 171, "unit": "count/min" }
      },
      "has_route": true
    }
  ],
  "routes": [
    { "workout_uuid": "...", "part": 1, "parts": 3, "points": [ { "t": "...", "lat": 52.37, "lon": 4.89, "alt": 2.1 } ] }
  ],
  "ecg": [
    {
      "uuid": "...",
      "start": "...", "end": "...",
      "classification": "sinusRhythm",
      "symptoms_status": "none",
      "avg_hr": 64,
      "sampling_hz": 512.0,
      "n_samples": 15360,
      "part": 1, "parts": 1,
      "voltages_uv_f32le": "<base64 of little-endian float32 microvolts>"
    }
  ],
  "state_of_mind": [
    { "uuid": "...", "start": "...", "kind": "momentaryEmotion", "valence": 0.4, "labels": ["calm"], "associations": ["work"], "source": { "bundle": "...", "name": "..." } }
  ],
  "deleted": [
    { "uuid": "...", "type": "HKQuantityTypeIdentifierBodyMass" }
  ]
}
```

The `app` block: `version` = `CFBundleShortVersionString`, `build` = `CFBundleVersion`, `os` = `UIDevice.current.systemVersion`, `model` = `utsname.machine` (for example `iPhone18,1`), `low_power` = `ProcessInfo.isLowPowerModeEnabled` when the body is built.

### Types and units

- `type` is the raw HealthKit identifier. The receiver accepts any identifier matching `^HK[A-Za-z]+TypeIdentifier[A-Za-z0-9]+$`, up to 300 distinct types, so new Apple types need no contract change.
- The app reads every quantity and category type it can, except: medications and clinical records (never), and ECG, State of Mind and workout routes, which are **off by default** and switched on one by one in onboarding, each named on the consent screen.
- Units: `contract/units.json` is normative. Every quantity sample and daily row carries exactly the unit string listed there for its type. Within `body_version` 1 an existing entry never changes; new types are only added. The entries beyond the 20 types pinned at first are generated by `contract/tools/gen_types.swift`, which also writes `contract/category.json` (the category identifiers the app may read).
- Percent types (unit `%`, for example `OxygenSaturation`, `BodyFatPercentage`) travel and are stored as HealthKit fractions from 0 to 1 (`0.97`), still with unit `%`. MCP output converts them to 0 to 100 and keeps `%`.
- A sample or daily row whose `unit` differs from `units.json` for a known type is stored, left out of every aggregation (raw output still shows it with its own unit), and counted in `sync_status` as `unit_mismatch_count`.
- Samples dated more than 1 day ahead (a wrong phone clock) are accepted and stored, and range queries return them. They never count as the newest or last data: a source's `last_seen`, `list_types` `last`, the watchdog and the app's per-type "last data" all skip them, and they skip daily rows and nights more than 1 day ahead too. `sync_status` counts them as `future_sample_count`.
- Category samples carry `value` (the integer) and no `unit`. `value_label`, the enum case name, is sent in v0 for `HKCategoryTypeIdentifierSleepAnalysis` (`inBed`, `asleepUnspecified`, `awake`, `asleepCore`, `asleepDeep`, `asleepREM`) and `HKCategoryTypeIdentifierAppleStandHour` (`stood`, `idle`); other category types send `value` only. Adding labels later is additive.
- Home time zone: set at pairing to the phone's zone and saved with the pairing. It drives the bucketing itself, not only the label: statistics queries are anchored at midnight in the home zone and sleep nights are computed with a calendar in the home zone. Daily and sleep-night rows send it as `tz`. Travel does not re-bucket history. Changing the home zone means "Pair again", or (later) a settings change that also runs "Resend from date".
- A sample's `tz` is `HKMetadataKeyTimeZone` when the sample has it, otherwise the phone's zone at read time. It is informational and does not affect buckets.
- The receiver stores `day` and `night` as sent and never recomputes them.

### Daily statistics

- Computed on the phone with `HKStatisticsCollectionQuery`, bucketed by day in the home time zone.
- Per-source rows for every quantity type (`.separateBySource`).
- `@merged` rows only for cumulative types (steps, energy, distance, exercise and stand time, flights, nutrition, water and the like). That is HealthKit's deduplicated total using the user's source priority, and it needs a second query without `.separateBySource`. Discrete types (heart rate, HRV, weight, SpO2) get no merged row, because HealthKit's cross-source average blends devices.
- `n` is the number of samples in the bucket where it is known, otherwise `null`. HealthKit statistics do not report a count, so the v0 app always sends `null`.
- `partial: true` marks the current day.
- Re-sent: the last 3 days on every sync, and the last 30 days once per 24 hours, so late writes and deletes that leave some data in a bucket are corrected. A `(type, source, day)` row whose data was all deleted is not sent again, so the stored row stays; v0 has no way to remove it (`replace_range`, App Store milestone, below).

### Sleep

- Raw sleep samples go in `samples` for fidelity.
- `sleep_nights` are computed on the phone: one row per source and one `@merged` row that resolves overlaps between devices.
- Grouping: per group (one source, or all sources for `@merged`), the intervals of every sleep value are merged (overlapping and touching intervals joined) and split into sessions at gaps over 2 hours. `night` is the date, in the home time zone, of a session's last end; sessions that end on the same date form one night (naps included).
- Minutes: `in_bed` is the merged union of all sleep intervals of that night (so `inBed` samples count, and so does time asleep); `asleep` is the merged union of core, deep, REM and unspecified; each stage is the merged union of its own intervals. `inBed` alone is never counted as sleep. Minutes are rounded to 2 decimals.
- `@merged` has one definition everywhere: `in_bed` and `asleep` only, no stage minutes and no segments (stages are never merged across writers). Per-source rows carry stages and segments.
- Recompute: on every wake window the phone recomputes every night touched by a sleep sample read in that window, by the sample's end date (the night of that date and the next one, since a session that continues past midnight ends there). Backfill and "Resend from date" recompute every night in their range. A deleted sleep sample does not say which night it belonged to; a resend that covers that night corrects it while some sleep data remains. A `(night, source)` row that no longer has any data (all samples deleted, or a session that grew past midnight and now belongs to the next night) is not sent again and stays in the store until `replace_range` (App Store milestone) removes it.

### Workouts, routes, ECG and State of Mind

- Workout `stats` are keyed by HealthKit identifier.
- Routes (opt-in) and ECG voltages can be large. They travel in `part`/`parts` chunks that fit the batch limits.
- ECG voltages come from `HKElectrocardiogramQuery`, converted from volts to microvolts, sent as float32 at the uniform `sampling_hz`. `classification` and `symptoms_status` are Apple's enum case names, passed on as data.
- State of Mind needs iOS 18. On iOS 17 the array is never sent. `kind`, `labels` and `associations` are enum case names; `valence` is −1 to 1.
- The v0 app reads none of these four kinds, so nothing is lost now. A v0 receiver accepts the arrays and exposes no tool for them; the deployed one logs and drops them (`body.py`, `IGNORED_ARRAYS`) and still answers `200 stored`. A v1 app that reaches a v0 receiver therefore loses them, and after the receiver is upgraded the user runs "Resend from date" for them. `accepts` in `/v1/status` (section 3, App Store milestone) prevents this: the phone sends these kinds only to a receiver that lists them. v1 adds them to the backfill order below.

### Deletes

- `deleted` comes from the anchored query's `HKDeletedObject`s. The type comes from the per-type anchor that reported it; every type has its own anchor.
- HealthKit may prune old deleted objects when the app has not run for a long time, so deletes are best effort.
- The receiver keeps a tombstone per deleted UUID. A tombstone wins: a later batch carrying that UUID does not bring it back.

### Backfill and "Resend from date"

1. First, an anchored query per type with a start date of now establishes the incremental anchors. Later incremental reads pass only the anchor and no date predicate, so samples synced late with old start dates still arrive.
2. Then backfill by date windows with `HKSampleQuery` / statistics queries, in this order: daily statistics for all history, sleep nights for 365 days, then raw samples newest to oldest for 365 days. Every user gets this range; there is no paid tier. Raw samples never go back more than 365 days, in any backfill or resend. Progress (the backfill cursor) is saved per window in the same outbox transaction as the batches it produced, so it resumes.
3. "Resend from date" (in v0) runs the backfill cursor from a chosen date: daily statistics and sleep nights for the whole range from that date to now, and raw samples only for the last 365 days of that range, in the order of step 2. It never replaces a running backfill or resend: it is queued behind it, and two queued requests merge into the earlier date. The receiver upserts samples by `uuid` and daily and sleep-night rows by their keys, so a resend is safe to repeat. It is the recovery path for dead-letter batches and for a changed receiver key. A resend sends what exists. It creates no tombstones and removes no stored rows, so samples deleted while no anchor was running (during a re-pair or reinstall) and rows whose data is all gone stay in the store.
4. `replace_range` (App Store milestone; v0 receivers and apps ignore it): a resend body may carry `"replace_range": [{"kind": "daily", "type": "<identifier>", "source": "<source>", "from": "<day>", "to": "<day>"}]` (`kind` `daily` or `sleep_nights`; `source` absent means every source of that type). The phone puts every row it resends for that type, source and range into the same batch as the entry. The receiver then deletes the stored rows of that kind, type and source in `[from, to]` that the batch did not include, so deleted data disappears.
5. v1 adds workouts, routes, ECG and State of Mind to step 2 for the opted-in kinds.

### Evolution

- Within `body_version` 1, changes are additive only. Removing or renaming means `body_version` 2; the receiver accepts the current and previous version and answers others with 426.

## 6. Receiver store

One SQLite database on a local Docker volume (not NFS or SMB; WAL files must sit next to the database), opened with WAL and `busy_timeout`.

```sql
sources(source PK, name, product_type, first_seen, last_seen)
samples(uuid PK, type, kind, start, end, value, value_label, unit, source REFERENCES sources, tz, metadata JSON)
  INDEX (type, start), INDEX (type, source, start), INDEX (end)
daily(type, source, day, tz, sum, avg, min, max, n, unit, partial, PRIMARY KEY (type, source, day))
sleep_nights(night, source, tz, start, end, minutes JSON, segments JSON, PRIMARY KEY (night, source))
workouts(uuid PK, activity, start, end, source, stats JSON, has_route)
routes(workout_uuid, part, points JSON, PRIMARY KEY (workout_uuid, part))
ecg(uuid PK, start, end, classification, symptoms_status, avg_hr, sampling_hz, n_samples, voltages BLOB)
state_of_mind(uuid PK, start, kind, valence, labels JSON, associations JSON, source)
tombstones(uuid PK, type, deleted_at)
batches(batch_id PK, device_id, seq, ciphertext_sha256, received_at, status, flags)
devices(device_id PK, name, signing_pk, paired_at, revoked_at)
```

- `source` values `@merged` cannot clash with HealthKit bundle IDs.
- `sources.last_seen` is the latest sample `end` no later than the batch's `received_at` plus 1 day, and `NULL` when a source has only later samples. On startup the receiver resets any `last_seen` later than now plus 1 day (left by stores written before this rule) to the latest sample end within that limit.
- Tombstones and batch records are kept 400 days.
- Free-text fields (`name`, labels, metadata strings) are stored at most 200 characters with control characters removed.
- Source names returned through MCP have control characters removed and are at most 64 characters. `source.bundle` (and a daily row's `source`, apart from `@merged`) is limited to the characters `[A-Za-z0-9._-]`. Line and paragraph separators (U+2028, U+2029) are removed and runs of whitespace become one space. Each source gets a stable ID of at most 64 characters: the bundle itself when it is already clean, otherwise its cleaned form plus a short hash, so two sources never merge. Tools accept that ID back as `source`, and `query` cursors carry the cleaned ID.
- The receiver makes a nightly SQLite backup to the volume and keeps 14. The store is the only full copy of the uploaded data.

## 7. MCP

### Transport and auth

- Docker receiver, from v0: streamable HTTP at `http://<receiver>/mcp` (for example `http://100.100.1.1:8796/mcp` on a tailnet), for Claude Code and other MCP clients that can reach it. v0 serves `list_types`, `list_sources`, `query`, `summary`, `get_sleep` and `sync_status`; the other tools follow in v1.
- Bearer tokens per client: `healthuplink tokens create --name claude-code`, stored hashed, revocable with `healthuplink tokens revoke`.
- Claude Desktop is not supported in v1. Its remote connectors run from Anthropic's cloud and cannot reach a tailnet address.
- The receiver serves `/mcp` with the official MCP Python SDK.

### Common response parts

Every tool result includes:

```json
"freshness": {
  "last_upload_at": "2026-11-22T07:30:12Z",
  "drained_at": null,
  "stale": false,
  "stale_after_hours": 18,
  "last_upload_low_power": false,
  "sources": [ { "source": "com.apple.health.DE15...", "name": "Apple Watch", "last_sample_at": "2026-11-22T07:10:00Z" } ]
}
```

- `sources` holds at most 20 sources, most recent `last_sample_at` first. Names follow the limits in section 6. The cap applies to `freshness` only.

- `last_upload_at` is the newest batch received from any device. `drained_at` is always `null`; it belonged to the replaced mailbox mode and stays for compatibility.
- `stale` is true when no batch arrived for `stale_after_hours`. Per-source `last_sample_at` shows which device is behind.
- `last_sample_at` (here and in `sync_status`) and `last_seen` (`list_sources`) are `null` for a source whose samples all end more than 1 day ahead (section 5). Such sources sort after every dated one, so `freshness.sources` shows them only when fewer than 20 sources have a date.
- `last_upload_low_power` copies `app.low_power` from the newest batch. Low Power Mode stopped background wake-ups in testing, so when it is true the likely cause of staleness is Low Power Mode, not a fault.
- Free-text values are returned inside data fields only, and tool descriptions say that such values are user data, not instructions.

### Tools (`tools_version` 1, all read-only)

| Tool | Arguments | Returns |
|---|---|---|
| `list_types()` | none | Each type with alias, kind, unit, cumulative or discrete, first and last timestamp, count. `first` and `last` come from the samples, or from the daily rows when no sample ends within 1 day of now; both are `null` when neither has such data |
| `list_sources()` | none | Sources with name, product type, first and last seen (`last_seen` may be `null`, see above). Names are cleaned as in section 6; the list is not capped |
| `query` | `type` (identifier or alias such as `heart_rate`), `from`, `to`, `aggregation` (`raw`, `hour`, `day`, `week`, `month`), `source` (optional), `limit` (default 1,000, max 5,000), `cursor` | Points with unit, `next_cursor` |
| `summary` | `period` (`day`, `week`, `month`), `end` (optional) | Steps, active energy, exercise minutes, resting heart rate, HRV, sleep total, deep and REM, weight: value, previous period, change |
| `get_sleep` | `from`, `to`, `source` (optional) | Without `source`: every source's nights (minutes per stage) plus the `@merged` night (`in_bed` and `asleep` only), and the result reports `source: null`. With `source`: that source's nights. Segments on request |
| `get_workouts` | `from`, `to`, `activity` (optional), `include_route` (default false) | Workouts with stats |
| `get_ecg` | `id` or `from`/`to`, `include_voltages` (default false), `downsample_hz` | Recordings with Apple's classification as data; downsampled voltages are flagged as lossy |
| `get_state_of_mind` | `from`, `to` | Entries |
| `sync_status()` | none | Per device: last upload, `high_contiguous_seq`, real gaps, dead-letter count, flags; per source (every source, not capped): last sample; `unit_mismatch_count` (rows stored with a unit that differs from `units.json`); `future_sample_count` (samples ending more than 1 day after now, added within `tools_version` 1) |

Aggregation rules for `query`:

- Cumulative types: `day` and coarser come from `daily` (`@merged` when no `source` is given); `week` and `month` sum the daily rows; `hour` sums raw samples of one source.
- Discrete types: `day` comes from `daily`. `week` and `month` combine daily rows weighted by `n`: average = sum of avg × n ÷ sum of n, min of the mins, max of the maxes. `n` is the sum of the known counts, and `null` when no row has one. A row without `n` weighs 1 in the average, so with v0 data (always `null`) the average is the plain mean of daily averages and `n` is `null`. Without `source`, results are grouped per source, never blended.
- Rows whose unit differs from `units.json` never enter an aggregate (section 5). `raw` still returns them, each labelled with its own `unit`. `query` reports the unit from `units.json`, also for a type with no data. Percent types are returned as 0 to 100 with unit `%`.
- `raw` without `source` returns all sources interleaved, each point tagged with its source.

Wording: tool descriptions describe data, never health conditions. The app UI never shows ECG classifications.
