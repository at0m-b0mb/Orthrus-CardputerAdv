# Orthrus

**Every LoRaWAN security tool needs a laptop, an SDR, or a gateway. This one fits in your pocket.**

A multi-surface red team platform for the M5Stack Cardputer-Adv. It listens to
the LoRaWAN devices around you, builds a census of them, and grades each one —
on battery, on a keyboard-sized device, with no host computer involved.

<p align="center">
  <img src="docs/screens/airspace.png" width="32%" alt="Live listening view">
  <img src="docs/screens/census.png"   width="32%" alt="Device census">
  <img src="docs/screens/dossier.png"  width="32%" alt="Per-device findings">
</p>

> Every number in those screenshots — each grade, confidence value and finding —
> was produced by the real parser, census and grader, not written by hand. See
> [tools/screendump](tools/screendump). If a grade in this README is wrong, the
> engine is wrong, and a test says so.

---

## Why this exists

LoRaWAN runs utility meters, building sensors, agricultural telemetry and asset
tracking. It is deployed at enormous scale and audited almost never, because
until now auditing it meant carrying a laptop and a software-defined radio.

Everything that exists today is tethered:

| Tool | Stars | Needs |
| --- | ---: | --- |
| [IOActive/laf](https://github.com/IOActive/laf) | 188 | Python, a gateway or SDR, a server |
| [seemoo-lab/chirpotle](https://github.com/seemoo-lab/chirpotle) | 42 | Laptop controller plus multiple Pi nodes |
| [konicst1/lorattack](https://github.com/konicst1/lorattack) | 28 | SDR |
| [CatWAN USB Stick](https://github.com/ElectronicCats/CatWAN_USB_Stick) | 49 | Tethered to a PC |

Orthrus is none of those. You walk a site with it.

---

## The rule that governs every finding

> **Presence is proof. Absence is not.**

A single SX1262 camps on **one channel at one spreading factor**. EU868 has
eight channels and six spreading factors — 48 combinations — so a parked radio
hears about **2%** of the band. US915 is far worse.

That fact drives the whole design:

- **Findings from what we saw** score at full weight. A frame counter that went
  backwards went backwards. Missing 98% of the band does not make the 2% we
  heard less true.
- **Findings from what we did not see** are capped by coverage, and below a 20%
  coverage floor they are not emitted at all. Instead the device says plainly:
  *"coverage too low to judge."*
- **Grades carry a provisional mark** when the evidence under them is thin. An
  A+ from 16% of the band should not read like an A+ from all of it.
- **No confidence value ever reaches 100.** A passive listener without keys
  cannot be certain, and a tool that prints certainty it has not earned is
  lying.

The signature element on screen is the **coverage grid**: all 48 channel/SF
cells drawn, with the one you are actually camped on lit. Your blind spot is
visible without reading a word. Press `h` and watch it fill in as the radio
hops.

---

## What it finds

Passively, without keys:

| Finding | Severity | How it is established |
| --- | --- | --- |
| Frame counter reset | Critical | Counter fell without wrapping — every frame below the old value is replayable |
| Join nonce reused | High | A DevNonce repeated; in LoRaWAN 1.0.x the join can be replayed |
| Payload not encrypted | High | FRMPayload is readable cleartext — no keys needed to prove it |
| MAC commands in two places | Medium | FPort 0 and FOpts populated together, which the spec forbids |
| Frame counter repeated | Medium | Same counter twice: retransmission or replay, and we say we cannot tell which |
| Rejoining repeatedly | Medium | Join churn well beyond a healthy device |
| ADR never set | Low | Stuck at a slow rate, burning airtime and battery |
| Every uplink confirmed | Low | Forces a downlink each time; an amplification surface |
| Stuck at high SF | Low | SF11/SF12 only: maximum airtime, loudest footprint |

Cleartext detection **refuses to speak below 8 bytes**. Ciphertext is
all-printable by luck roughly once in 2,700 at that length, and calling that
plaintext would be a lie dressed as a finding.

---

## Hardware

| Part | Notes |
| --- | --- |
| [M5Stack Cardputer-Adv](https://shop.m5stack.com/products/m5stack-cardputer-adv-version-esp32-s3) | ESP32-S3, 8 MB flash, **no PSRAM** |
| [Cap LoRa-1262](https://shop.m5stack.com/products/cap-lora-1262-for-cardputer-adv-sx1262-atgm336h) | SX1262 + ATGM336H GPS |

### Pin map, verified on hardware

M5's own documentation for the cap is wrong in two places: it labels NSS as
"SCK", and it puts the GPS on G8/G9, which is the internal I²C bus shared by the
codec, IMU and keyboard controller. Following the docs gets you a radio that
never answers. These values were confirmed with a bring-up probe on real
silicon:

| SX1262 | GPIO | | ATGM336H GPS | GPIO |
| --- | --- | --- | --- | --- |
| SCK / MOSI / MISO | 40 / 14 / 39 — **shared with microSD** | | ESP32 RX ← GPS TX | 15 |
| NSS | **5** | | ESP32 TX → GPS RX | 13 |
| RST / BUSY / DIO1 | 3 / 6 / 4 | | UART2 @ 115200 | — |

The radio also needs **TCXO at 1.8 V on DIO3** and **DIO2 driving the RF
switch** — neither is RadioLib's default. Measured across four configurations at
868.1 MHz: TCXO voltage makes no difference to the receive floor, while DIO2 as
RF switch shows the wider spread of a front end genuinely connected to the
antenna.

With the cap fitted, **Grove Port A is the only expansion left**. NFC (0x50) and
RFID2 (0x28) are both I²C and can share it; the IR unit needs those same pins as
GPIO, so it cannot be present at the same time.

---

## Build

```bash
pio run -t upload
```

Run the engine tests — no board required:

```bash
pio test -e native
```

Regenerate the documentation screenshots from the engine:

```bash
g++ -std=c++17 -I lib/core tools/screendump/main.cpp lib/core/lorawan/*.cpp -o build/screendump
./build/screendump > build/screens.json && python3 tools/render_mockups.py
```

---

## Layout

Anything that decides whether a finding is true lives in `lib/core`, builds on
the host, and is covered by tests. The firmware is glue around it.

```
lib/core/lorawan/    parser, census, grader, channel plans   <- host-tested
src/hal/             board pins, SX1262 receive path
src/app/             design tokens and drawing
src/modules/         Airspace: the live listening surface
test/native/         53 tests, no hardware needed
tools/               screendump + mockup renderer
```

---

## Status

| Surface | State |
| --- | --- |
| **Airspace** — LoRa/LoRaWAN census and grading | Working |
| **Perimeter** — Wi-Fi recon and captive portals | Not built |
| **Credentials** — NFC and 125 kHz badge work | Not built |
| **Control** — infrared and USB payloads | Not built |
| **Engagement** — scope, evidence log, export | Not built |

Unbuilt surfaces say so on screen rather than presenting empty menus.

**Not yet proven:** the receive front end is confirmed alive (plausible noise
floor, correct response to configuration), but decoding real over-the-air
LoRaWAN has not been demonstrated yet — that needs live traffic to listen to.
Said here rather than left for you to discover.

---

## What this deliberately does not do

**No deauthentication, jamming, or RF/BLE flooding.** Not an oversight — a
decision, for three reasons. It is denial of service rather than assessment. It
is the single feature that gets devices like this pulled from sale and their
sellers into regulatory trouble. And it is unnecessary: a captive-portal evil
twin works on new associations, and detecting deauth is better served by a
purpose-built detector.

---

## Authorized use only

Orthrus is built for security professionals testing systems they have written
permission to test. Passive listening is lawful in most jurisdictions;
transmitting is not always, and LoRaWAN duty-cycle rules vary by region.
Understand your local regulations. You are responsible for what you point it at.

---

## Licence

MIT. See [LICENSE](LICENSE).
