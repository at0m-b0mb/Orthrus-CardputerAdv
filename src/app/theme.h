// Design tokens.
//
// One place where colour and type are decided, so no widget hand-picks either.
//
// The ground is true black, not dark navy -- this is a field instrument, read
// in the dark, and black is both correct for the house style and cheaper on the
// panel. Gold is the single accent, and it is two tokens rather than one: a
// deep brass that stays legible at 6 px, and a bright shine used only on marks
// that carry no text. One gold cannot do both jobs.
//
// Severity colours are functional, not decorative -- they encode a grade, so
// they are allowed to exist alongside the accent. None of them are blue.

#pragma once

#include <M5Cardputer.h>

#include <cstdint>

namespace orthrus::theme {

// M5GFX wants RGB565. Declaring tokens as literal hex keeps them reviewable
// against the same values used everywhere else in the catalogue.
constexpr uint16_t rgb(uint8_t r, uint8_t g, uint8_t b) {
    return static_cast<uint16_t>(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

// ---- ground ----------------------------------------------------------------
inline constexpr uint16_t kInk     = rgb(0x00, 0x00, 0x00);  // canvas, true black
inline constexpr uint16_t kSurface = rgb(0x14, 0x13, 0x11);  // raised panel
inline constexpr uint16_t kRule    = rgb(0x33, 0x30, 0x2B);  // hairline

// ---- text ------------------------------------------------------------------
inline constexpr uint16_t kText   = rgb(0xED, 0xE9, 0xE0);  // warm white
inline constexpr uint16_t kMuted  = rgb(0x8A, 0x85, 0x7C);
inline constexpr uint16_t kFaint  = rgb(0x5A, 0x56, 0x50);

// ---- accent: two golds, deliberately ---------------------------------------
inline constexpr uint16_t kBrass = rgb(0xB8, 0x89, 0x3B);  // small text, labels
inline constexpr uint16_t kShine = rgb(0xE8, 0xB4, 0x4A);  // marks only, no text

// ---- severity --------------------------------------------------------------
inline constexpr uint16_t kCritical = rgb(0xD9, 0x48, 0x3B);
inline constexpr uint16_t kHigh     = rgb(0xE0, 0x7A, 0x2F);
inline constexpr uint16_t kMedium   = rgb(0xD9, 0xA9, 0x3B);
inline constexpr uint16_t kLow      = rgb(0x7E, 0x8C, 0x6A);
inline constexpr uint16_t kInfo     = rgb(0x8A, 0x85, 0x7C);
inline constexpr uint16_t kGood     = rgb(0x6F, 0xA8, 0x6B);

// ---- type ------------------------------------------------------------------
// A serif for identity and grades, a sans for controls, a mono for data the
// operator reads digit by digit. That mix is most of what stops a UI looking
// like a framework default.
inline const auto* kFaceIdentity = &fonts::FreeSerifBold9pt7b;
inline const auto* kFaceUi       = &fonts::FreeSans9pt7b;
inline const auto* kFaceData     = &fonts::Font0;  // 6x8 fixed, dense and exact

// ---- rhythm ----------------------------------------------------------------
inline constexpr int kPad       = 4;
inline constexpr int kHeaderH   = 16;
inline constexpr int kFooterH   = 12;
inline constexpr int kRowH      = 14;

}  // namespace orthrus::theme
