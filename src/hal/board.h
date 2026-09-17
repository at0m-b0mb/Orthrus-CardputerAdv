// Cardputer-Adv pin map, with the Cap LoRa-1262 fitted.
//
// Every value here was verified against the board itself on 2026-09-16 by the
// bring-up probe, not copied from a product page. That matters: M5's own
// documentation for the cap lists "SCK = G5", which is actually NSS, and lists
// the GPS on G8/G9, which is the internal I2C bus shared by the codec, the IMU
// and the keyboard controller. Following the docs gets you a radio that never
// answers.

#pragma once

#include <cstdint>

namespace orthrus::board {

// ---- SX1262 on the Cap LoRa-1262 -------------------------------------------
// Shares SPI with the microSD card; only the chip selects differ. Verified: the
// radio still responds after the SD driver has used the bus.
inline constexpr int kLoraSck  = 40;
inline constexpr int kLoraMosi = 14;
inline constexpr int kLoraMiso = 39;
inline constexpr int kLoraCs   = 5;
inline constexpr int kLoraRst  = 3;
inline constexpr int kLoraBusy = 6;
inline constexpr int kLoraDio1 = 4;

// This module has no separate RX/TX enable lines, so DIO2 drives the RF switch
// and DIO3 powers the TCXO at 1.8 V. RadioLib defaults to 1.6 V, which is not
// what this hardware expects.
inline constexpr bool  kLoraDio2AsRfSwitch = true;
inline constexpr float kLoraTcxoVolts      = 1.8f;

// ---- ATGM336H GPS ----------------------------------------------------------
inline constexpr int      kGpsRx   = 15;  // ESP32 receives here
inline constexpr int      kGpsTx   = 13;
inline constexpr uint32_t kGpsBaud = 115200;  // measured: 32 NMEA sentences in 2.5 s

// ---- microSD ---------------------------------------------------------------
inline constexpr int kSdCs = 12;

// ---- Grove ports -----------------------------------------------------------
// There are TWO once the LoRa cap is fitted, which an earlier version of this
// file got wrong:
//
//   Port A on the board itself  G1 = SCL, G2 = SDA   (M5.Ex_I2C)
//   the cap's pass-through      G9 = SCL, G8 = SDA   (M5.In_I2C, shared with
//                                                     the codec, IMU and
//                                                     keyboard controller)
//
// Verified on hardware 2026-09-16 with both units fitted: the NFC Universal
// answered at 0x50 on Port A and the RFID2 at 0x28 on the cap port, at the same
// time. So both readers can be connected at once.
//
// The IR unit needs Port A's pins as plain GPIO, so it cannot coexist with an
// I2C unit on THAT port -- but it can sit on Port A while a reader uses the cap.
inline constexpr int kGroveSda = 2;
inline constexpr int kGroveScl = 1;

inline constexpr uint8_t kAddrNfcUniversal = 0x50;
inline constexpr uint8_t kAddrRfid2        = 0x28;

// ---- Unit IR (SKU U002) on the Grove port ----------------------------------
//
// Established 2026-09-17 from M5Stack's own documentation, schematic and
// shipped example, five sources agreeing:
//
//   yellow wire = IR_TX  -> G2   active HIGH, drives an SS8050 into the LED
//   white wire  = IR_RX  -> G1   IRM-3638T demodulated output
//
// The receiver IDLES HIGH and pulls LOW while it hears 38 kHz carrier -- M5's
// own example says so in a comment on the pin read ("0: detected"). So a
// falling edge starts a mark, and the decode logic is inverted with respect to
// the transmitted waveform. IrRx discovers this by sampling the idle level
// rather than trusting it, but this is the expected answer.
//
// ONE HARDWARE CAUTION, NOT VERIFIED WITH A METER
//
// The unit pulls that output up to ITS OWN VCC through 4.7k, and the Grove red
// wire on this board is 5 V. If the pull-up really sits at 5 V then G1 idles
// above the ESP32-S3 absolute maximum. M5 sells this unit for exactly these
// hosts so the combination evidently survives, but nothing in their docs says
// it is level shifted. Worth a meter before blaming firmware for anything odd.
inline constexpr int kIrUnitRx = 1;   // white,  = kGroveScl
inline constexpr int kIrUnitTx = 2;   // yellow, = kGroveSda

// ---- onboard ---------------------------------------------------------------
inline constexpr int kIrEmitter = 44;  // emitter only; the Adv has no receiver

// ---- display ---------------------------------------------------------------
inline constexpr int kScreenW = 240;
inline constexpr int kScreenH = 135;

}  // namespace orthrus::board
