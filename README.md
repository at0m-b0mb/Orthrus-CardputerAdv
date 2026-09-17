<p align="center">
  <img src="docs/brand/orthrus-banner.svg" alt="Orthrus — handheld LoRaWAN security assessment" width="100%">
</p>

<p align="center">
  <a href="https://github.com/at0m-b0mb/Orthrus-CardputerAdv/actions/workflows/ci.yml"><img src="https://github.com/at0m-b0mb/Orthrus-CardputerAdv/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/host%20tests-292%20passing-6FA86B" alt="292 host tests">
  <img src="https://img.shields.io/badge/on--device%20tests-52%20passing-6FA86B" alt="52 on-device tests">
  <img src="https://img.shields.io/badge/platform-Cardputer--Adv-B8893B" alt="Cardputer-Adv">
  <img src="https://img.shields.io/badge/licence-MIT-8A857C" alt="MIT">
</p>

> **Every LoRaWAN security tool needs a laptop, an SDR, or a gateway. This one fits in your pocket.**

Orthrus listens to the LoRaWAN devices around you, builds a census of them, and
grades each one — on battery, on a keyboard-sized device, with no host computer
involved.

> The spectrum trace in the banner above is not an illustration. It is the real
> 863–930 MHz sweep this device measured, read out of its own self-test log.

---

<p align="center">
  <img src="docs/screens/airspace.png" width="32%" alt="Live listening view">
  <img src="docs/screens/census.png"   width="32%" alt="Device census">
  <img src="docs/screens/dossier.png"  width="32%" alt="Per-device findings">
</p>

> Every grade, confidence value and finding in those screenshots came out of the
> real parser, census and grader — see [tools/screendump](tools/screendump). If a
> grade here is wrong, the engine is wrong, and a test says so. CI rebuilds them
> from the engine on every push.

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

> ### Presence is proof. Absence is not.

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
- **Claims we cannot separate from our own tuning are not made.** Parked on
  SF12, every device you can hear *is* at SF12 — so "stuck at a high spreading
  factor" is only ever reported when more than one was actually swept.
- **No confidence value ever reaches 100.** A passive listener without keys
  cannot be certain, and a tool that prints certainty it has not earned is
  lying.

The signature element on screen is the **coverage grid**: all 48 channel/SF
cells drawn, with the one you are camped on lit. Your blind spot is visible
without reading a word. Press `h` and watch it fill in as the radio hops.

---

## What it finds

Passively, without keys:

| Finding | Severity | How it is established |
| --- | --- | --- |
| Frame counter reset | Critical | A counter fell without wrapping — every frame below the old value is replayable |
| Join nonce reused | High | A DevNonce repeated; in LoRaWAN 1.0.x the join can be replayed |
| Payload not encrypted | High | FRMPayload is readable cleartext — no keys needed to prove it |
| MAC commands in two places | Medium | FPort 0 and FOpts populated together, which the spec forbids |
| Frame counter repeated | Medium | Same counter twice: retransmission or replay, and we say we cannot tell which |
| Rejoining repeatedly | Medium | Join churn well beyond a healthy device |
| ADR never set | Low | Stuck at a slow rate, burning airtime and battery |
| Every uplink confirmed | Low | Forces a downlink each time; an amplification surface |
| Stuck at high SF | Low | SF11/SF12 only — reported only if several SFs were swept |

Cleartext detection **refuses to speak below 8 bytes**. Ciphertext is
all-printable by luck roughly once in 2,700 at that length, and calling that
plaintext would be a lie dressed as a finding.

---

## Spectrum

Sweeping the band at ~1 second per pass, with max-hold so bursty transmitters
are visible at all. It began life as the measurement that proved the radio
genuinely retunes; it stayed because "what is transmitting around here?" is a
question worth answering before you know which protocol to point at.

Entering it says **capture paused** on screen, because one radio cannot sweep
and listen at the same time and pretending otherwise would be dishonest.

---

## Credentials

Hold a badge to the reader and Orthrus tells you what it is, what it relies on
for security, and how hard it would be to copy — all from anticollision alone,
which is exactly what someone standing next to you in a lift gets.

A real badge, read on hardware:

```
ATQA 0004  SAK 08  UID 0B701E59  (4-byte)
family Mifare Classic 1K, cipher Crypto1 (broken)
GRADE F (15/100)  [surface read only]
   CRITICAL  Broken cipher (Crypto1)     97%
   MEDIUM    4-byte UID                  90%
   INFO      Reader policy not visible
   INFO      No key probe attempted
```

### The ceiling that shapes this too

**You can read a badge. You cannot see what the reader does with it** — and the
overwhelming majority of access control installations compare the UID and
nothing else. A UID is broadcast unauthenticated by every card ever made. Against
a UID-only reader, the finest DESFire on the market is a number anyone can copy.

So **no card can earn A+ from a read alone**, and the device says why. The grade
describes the credential's potential; the control that actually matters is
invisible from where we are standing.

Grading is by how hard the credential is to copy. Crypto1 has been publicly
broken since 2008, so a Classic cannot be graded sound however tidy it is. A card
with nothing to authenticate against grades worse still, because it needs no
attack at all. And a published key that actually opened a sector is the worst
thing the tool can find, because we did it rather than inferred it.

Two identification subtleties a naive SAK lookup gets wrong: a card setting both
the ISO-DEP and Crypto1 bits is reported as **the weaker half**, because the
Crypto1 sectors are what an attacker will go for; and a 4-byte UID beginning
`0x08` is random-per-session by spec, so it is a privacy feature and is not
scored as a cloneable identifier.

The WS1850S driver is written out rather than pulled from an MFRC522 library:
every byte it parses comes off a card an attacker may have built, so the length
handling is the security-relevant part and it should not be buried in a
dependency. It trusts the measured frame length over anything the card claims.

---

## Harvest — WPA handshakes and PMKID

Turns "the network uses WPA2" into a finding a client can act on: a captured
handshake means the passphrase is subject to offline guessing, at the attacker's
own pace, with nothing on the network able to see it happening or slow it down.

**Passive, deliberately.** The usual way to force a handshake is to knock a
client off the network and watch it reconnect. Orthrus does not do that. It
listens — clients join networks constantly, and PMKID capture needs no client at
all. The cost is honest and the screen says it out loud: you may sit on a
channel and hear nothing, and that is a quiet channel, not a secure network.

It produces two files per session:

```
/orthrus/harvest-NNN.22000   hashcat mode 22000, ready to crack elsewhere
/orthrus/harvest-NNN.pcap    the frames themselves, for Wireshark or hcxtools
```

Cracking happens on a laptop with a GPU. This device captures and names what it
has; it never claims to have recovered a passphrase, and a twenty-character
random passphrase produces exactly the same capture as `password1`.

Three details that decide whether a capture actually cracks, all covered by
tests:

- **Targets are keyed on the (access point, station) pair.** A busy AP runs a
  separate handshake with every client, each with its own nonces and counters.
  Mixing two produces a hash line that is internally inconsistent and will never
  crack.
- **The stored EAPOL frame has its MIC field zeroed**, because that is the form
  both endpoints hashed.
- **Replay counters are checked**, and when they do not line up the line is
  still written — flagged, so the pairing is never mistaken for a
  protocol-verified one.

The channel lock (`l`) is the tactic that matters. Hopping means being deaf to
twelve channels out of thirteen; once a target is chosen, staying on its channel
is what catches the handshake. Dwell is three times longer on 1, 6 and 11, where
almost every access point lives.

Timestamps in the pcap come from `millis()` — this board has no real-time clock,
so a capture opens at the epoch. The times are correct relative to each other,
which is what reading a handshake needs.

---

## Proximity — Bluetooth

Every phone, earbud, watch and luggage tag in a room shouts a small unencrypted
packet several times a second. Proximity sorts that into things that matter.

**The claim it will not make:** seeing a tracker is not seeing a stalker. A Find
My advert means an Apple device is in offline-finding mode within about ten
metres, right now. Whether it is *following* you is a different question — it
needs the same tag seen in several places over hours — and the screen says so
rather than raising an alarm it has not earned.

Classification is drawn only from fields whose meaning is assigned by a registry
or a published protocol. A device called "AirTag" classifies as a generic
device, because a name is a string somebody typed.

It also reports the one privacy fact that decides everything else: whether an
address is **stable or rotating**. A resolvable private address changes every
few minutes and cannot be followed between sightings at all.

Passive by default. An **active** scan (`a`) transmits a scan request to every
device it hears, which is how you get names out of devices that do not advertise
one — and which means the device is no longer silent. That is a decision the
operator makes knowingly, never a default.

---

## Keys — Mifare Classic sector sweep

Credentials answers "what is this badge and how exposed is it" from
anticollision alone. Keys answers what a client asks next: open it. Every
sector, both key types, every published key, then read what is behind the ones
that opened.

The difference matters. A site that left the factory key on sector 0 and
diversified the rest has a different problem from one that left all sixteen, and
a report saying "default key accepted" cannot tell them apart. The sector map
shows opened, tried-and-refused, and never-tried as three different things.

**Read only.** It authenticates and reads. It never writes a block, never
changes a key, never touches an access condition — an authorized test that
bricks somebody's access card is a failed test.

**And it is not a cracker.** No nested attack, no darkside, no hardnested. If a
sector does not open with a published key, the honest answer on the screen is
that we could not open it — not a longer grind that eventually claims a key this
device never recovered.

---

## Position — GNSS

Three states, kept visibly distinct because they need completely different
responses and look identical on a lazy screen: **nothing** (no NMEA at all — a
seating problem), **receiving** (sentences parsing, no fix yet), and **fix**.

A fix comes with the radius it is actually good to, not just six decimal places.
HDOP times a nominal 5 m user range error, rounded up, floored at the receiver's
own limit — an order-of-magnitude statement, and the basis is written down. A
device that quotes a two metre radius it cannot deliver is worse than one that
quotes five.

Waypoints (`m`) go into the evidence chain, not just into RAM, so they come out
in the KML export with every other finding. A track log (`t`) writes a position
every ten seconds.

It also separates a bad sky from bad wiring: a receiver failing its own NMEA
checksums is a cable fault, and the two look identical if you only count good
sentences.

---

## Payload (BadUSB)

The ESP32-S3's native USB lets the Cardputer present itself as a keyboard and
type a DuckyScript the operator wrote. It needs no extra hardware.

```bash
pio run -e cardputer-adv-hid -t upload
```

**Why a separate build.** HID requires TinyUSB (`ARDUINO_USB_MODE=0`), and the
default build uses the hardware USB-JTAG — which is exactly why flashing it
never needs the BOOT button. Under mode 0 esptool cannot reset the board on its
own, so that environment runs a 1200-baud touch reset before upload, which the
Arduino USB stack answers by rebooting into the ROM bootloader. Measured, not
assumed: without the touch, flashing fails with *"No serial data received"*.

**How it behaves:**

- Payloads come from **your** SD card, in `/orthrus/payloads`. None are shipped
  onto it. A payload should be one you have read; there is a harmless example in
  [docs/payloads](docs/payloads) to copy across and try.
- Nothing runs on boot, on plug-in, or on opening the screen.
- The script is **parsed and validated before it can be armed**, so an
  unrecognised line is found in your hand rather than in front of a target. The
  screen names the line number and the offending word.
- Arming and firing are separate keys, and backing out always disarms.
- Any key aborts mid-run, modifiers are always released, and every run is
  written to the evidence log.

The keymap is US layout and the code says so. A payload written for US typed
against a UK or German layout produces mangled input, because the host decides
what a keycode means.

---

## Evidence integrity

A capture that ends as an editable CSV is an anecdote. Orthrus links every
record with a SHA-256 hash chain:

```
head(n) = SHA256( head(n-1) || record(n) )
```

Change, insert, delete or reorder anything in the middle of the log and every
digest from that point on stops matching. Verification is offline and needs no
key.

**What it does not prove, stated plainly:** anyone who can rewrite the whole
file can recompute the whole chain. A keyless chain cannot stop that. What
closes the gap is recording the head digest somewhere the file cannot reach —
which is why the device shows it on screen at the end of a session. Verified
against a head recorded that way, the log is genuinely tamper-evident. It also
proves nothing about *who* produced the log; that needs a signing key, and a
signing key on a device an attacker may be holding is not a signature anyone
should trust.

Both properties, including the limitation, are covered by tests.

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
never answers.

| SX1262 | GPIO | | ATGM336H GPS | GPIO |
| --- | --- | --- | --- | --- |
| SCK / MOSI / MISO | 40 / 14 / 39 — **shared with microSD** | | ESP32 RX ← GPS TX | 15 |
| NSS | **5** | | ESP32 TX → GPS RX | 13 |
| RST / BUSY / DIO1 | 3 / 6 / 4 | | UART2 @ 115200 | — |

The radio also needs **TCXO at 1.8 V on DIO3** and **DIO2 driving the RF
switch** — neither is RadioLib's default.

### Two Grove ports, not one

An earlier version of this README claimed the board's Port A was the only
expansion left with the cap fitted. That was wrong. **The LoRa cap carries its
own Grove port**, so both readers can be connected at once — confirmed on
hardware with both units plugged in:

```
portA(G1/G2)  0x50  NFC Universal (ST25R3916)
cap  (G8/G9)  0x28  RFID2 (WS1850S)
```

| Port | Pins | Bus |
| --- | --- | --- |
| Board's Port A | G1 = SCL, G2 = SDA | `M5.Ex_I2C` |
| Cap pass-through | G9 = SCL, G8 = SDA | `M5.In_I2C` — shared with the codec, IMU and keyboard |

The IR unit needs Port A's pins as plain GPIO, so it cannot share *that* port
with an I²C unit — but it can sit on Port A while a reader uses the cap's.

---

## Install

Grab `orthrus-<version>-cardputer-adv.bin` from
[Releases](https://github.com/at0m-b0mb/Orthrus-CardputerAdv/releases) and flash
it. The ESP32-S3's ROM USB-JTAG always answers, so **you never need to hold the
BOOT button**:

```bash
esptool --port /dev/cu.usbmodem2101 write-flash 0x0 orthrus-cardputer-adv.bin
```

Or build it yourself:

```bash
pio run -t upload
```

### Keys

| Key | Does |
| --- | --- |
| `;` `.` `,` `/` | Move — all four on the category grid, up/down in a list |
| `enter` | Open |
| `` ` `` | Back |
| `h` | Toggle channel hopping (Airspace) |
| `s` | Step spreading factor (Airspace) · save capture (Harvest) |
| `x` | Spectrum sweep (Airspace) |
| `c` | Clear the capture (Airspace) |
| `r` | Badge roll (Credentials) · retry the card (Engagement) |
| `m` | Clear max-hold (Spectrum) · mark a waypoint (Position) |
| `l` | Lock to this target's channel (Harvest) |
| `k` | Sweep every sector (Keys) |
| `f` | Trackers only (Proximity) |
| `a` | Active scan (Proximity) — transmits, see above |
| `t` | Track log on/off (Position) |
| `w` | Waypoint list (Position) |
| `e` | Export KML (Engagement) |

---

## Testing

Anything that decides whether a finding is true lives in `lib/core`, builds on
the host, and is covered by tests. The firmware is glue around it.

```bash
pio test -e native            # 292 host tests, no board required
pio run -e selftest -t upload # 35 checks on the real device
```

The on-device self-test exists because host tests cannot prove the ESP32 build
agrees, that the radio really retunes, or that the radio and SD card keep
coexisting on one SPI bus. **Its first run crashed the board** — `sizeof(Census)`
is 19,984 bytes and the Arduino `loopTask` stack is 8 KB — which is exactly the
sort of thing it is for.

What it establishes on real hardware:

- the target build parses, grades and scores identically to the host
- the radio really retunes: sweeping 863–930 MHz gives a floor from −116.9 to
  −103.6 dBm with **13.3 dB of frequency-dependent structure**, where a stuck
  synthesiser would read flat
- 150 rounds of interleaved SD writes and radio retunes: **zero errors** on
  either side of the shared bus
- 20,000 frames through census and grader leak **exactly zero bytes**
- a full 116-bin spectrum sweep completes in **1,077 ms**

The parser is additionally fuzzed under AddressSanitizer and UndefinedBehaviour
Sanitizer — 3,000,000 hostile frames, zero findings — and that runs in CI.

---

## Layout

```
lib/core/lorawan/    parser, census, grader, channel plans   <- host-tested
lib/core/dot11/      802.11 frames, EAPOL, hashcat and pcap   <- host-tested
lib/core/ble/        BLE advert parsing and classification    <- host-tested
lib/core/credential/ badge identification and grading         <- host-tested
lib/core/wifi/       network identification and grading       <- host-tested
lib/core/geo/        position formatting and error estimates  <- host-tested
lib/core/ir/         infrared protocol encoders               <- host-tested
lib/core/ducky/      HID keymap and DuckyScript parser        <- host-tested
lib/core/crypto/     SHA-256, checked against the NIST vectors
lib/core/evidence/   tamper-evident hash chain
src/hal/             board pins, SX1262 receive path, WS1850S reader
src/app/             design tokens, drawing, category glyphs
src/modules/         one file per surface
test/native/         292 tests, no hardware needed
tools/               screendump, mockup renderer, brand generator
```

---

## Status

| Category | Surface | State |
| --- | --- | --- |
| Wi-Fi | **Perimeter** — survey, graded, geotagged | Working |
| Wi-Fi | **Harvest** — WPA handshake and PMKID capture | Working |
| Bluetooth | **Proximity** — BLE device and tracker recon | Working |
| NFC | **Credentials** — 13.56 MHz badge identify and grade | Working |
| RFID | **Keys** — Mifare Classic sector key sweep | Working |
| Infrared | **Control** — room control | Working (transmit; capture needs the IR unit) |
| LoRa | **Airspace** — LoRa/LoRaWAN census and grading | Working |
| LoRa | **Spectrum** — live band sweep with max-hold | Working |
| GPS | **Position** — live fix, waypoints, track log | Working |
| USB | **Payload** — keyboard scripts | Working, in the `cardputer-adv-hid` build |
| System | **Engagement** — evidence log, chain head, KML export | Working |
| System | **Instruments** — live power, radio, GNSS, tilt | Working |

The menu is two levels: nine category tiles that fit on one screen with no
scrolling, then the tools inside one. The first thing an operator knows when
they pick the device up is which radio they are about to point at something, so
that is the first choice.

**Not yet proven:** the receive front end is confirmed alive and confirmed to
retune, but decoding real over-the-air LoRaWAN has not been demonstrated yet —
that needs live traffic to listen to. Said here rather than left for you to
discover.

---

## What this deliberately does not do

**No deauthentication, jamming, or RF/BLE flooding.** Not an oversight — a
decision, for three reasons. It is denial of service rather than assessment. It
is the single feature that gets devices like this pulled from sale and their
sellers into regulatory trouble. And it is unnecessary: Harvest catches
handshakes from clients joining on their own, and PMKID capture needs no client
at all.

**No key recovery against Crypto1.** Keys tries the published dictionary and
stops. No nested, darkside or hardnested attack. If a sector does not open with
a key anyone can look up, the finding is that we could not open it.

**No passphrase cracking on the device.** Harvest exports a hashcat file. A
handheld pretending to crack WPA would be pretending.

---

## Authorized use only

Orthrus is built for security professionals testing systems they have written
permission to test. Passive listening is lawful in most jurisdictions;
transmitting is not always, and LoRaWAN duty-cycle rules vary by region.
Understand your local regulations. You are responsible for what you point it at.

---

## Licence

MIT. See [LICENSE](LICENSE).
