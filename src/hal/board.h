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

// ---- Grove Port A ----------------------------------------------------------
// The only external expansion left once the cap is fitted. The NFC Universal
// Unit (0x50) and RFID2 (0x28) are both I2C and can share it; the IR unit needs
// these same pins as plain GPIO, so it cannot be present at the same time.
inline constexpr int kGroveSda = 2;
inline constexpr int kGroveScl = 1;

inline constexpr uint8_t kAddrNfcUniversal = 0x50;
inline constexpr uint8_t kAddrRfid2        = 0x28;

// ---- onboard ---------------------------------------------------------------
inline constexpr int kIrEmitter = 44;  // emitter only; the Adv has no receiver

// ---- display ---------------------------------------------------------------
inline constexpr int kScreenW = 240;
inline constexpr int kScreenH = 135;

}  // namespace orthrus::board
