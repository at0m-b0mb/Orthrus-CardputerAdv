// USB HID keyboard usage codes, and the US layout that maps characters to them.
//
// Pure and host-testable, which matters more here than almost anywhere else in
// this project: a wrong keycode does not fail loudly, it types a DIFFERENT
// character into somebody's machine. On an authorized engagement that is a
// wasted trip; on the wrong machine it is worse.
//
// US layout only, and the code says so rather than pretending otherwise. A
// payload written for US typed against a UK, German or French layout produces
// mangled input, because the host decides what a keycode means, not us.

#pragma once

#include <cstdint>

namespace orthrus::ducky {

// HID modifier bits (USB HID 1.11, section 8.3).
inline constexpr uint8_t kModCtrl  = 0x01;
inline constexpr uint8_t kModShift = 0x02;
inline constexpr uint8_t kModAlt   = 0x04;
inline constexpr uint8_t kModGui   = 0x08;

// Usage codes from the HID Usage Tables, keyboard page (0x07).
inline constexpr uint8_t kKeyNone       = 0x00;
inline constexpr uint8_t kKeyA          = 0x04;
inline constexpr uint8_t kKeyEnter      = 0x28;
inline constexpr uint8_t kKeyEscape     = 0x29;
inline constexpr uint8_t kKeyBackspace  = 0x2A;
inline constexpr uint8_t kKeyTab        = 0x2B;
inline constexpr uint8_t kKeySpace      = 0x2C;
inline constexpr uint8_t kKeyCapsLock   = 0x39;
inline constexpr uint8_t kKeyF1         = 0x3A;
inline constexpr uint8_t kKeyPrintScr   = 0x46;
inline constexpr uint8_t kKeyScrollLock = 0x47;
inline constexpr uint8_t kKeyPause      = 0x48;
inline constexpr uint8_t kKeyInsert     = 0x49;
inline constexpr uint8_t kKeyHome       = 0x4A;
inline constexpr uint8_t kKeyPageUp     = 0x4B;
inline constexpr uint8_t kKeyDelete     = 0x4C;
inline constexpr uint8_t kKeyEnd        = 0x4D;
inline constexpr uint8_t kKeyPageDown   = 0x4E;
inline constexpr uint8_t kKeyRight      = 0x4F;
inline constexpr uint8_t kKeyLeft       = 0x50;
inline constexpr uint8_t kKeyDown       = 0x51;
inline constexpr uint8_t kKeyUp         = 0x52;
inline constexpr uint8_t kKeyNumLock    = 0x53;
inline constexpr uint8_t kKeyApplication = 0x65;

struct KeyStroke {
    uint8_t modifiers = 0;
    uint8_t keycode   = kKeyNone;

    bool valid() const { return keycode != kKeyNone; }
};

// Maps one printable character to the keystroke that produces it on a US
// layout. Returns an invalid KeyStroke for anything it cannot type, rather
// than guessing -- silently dropping a character is better than sending the
// wrong one, and the caller can report it.
KeyStroke keyForChar(char c);

// Maps a DuckyScript key name ("ENTER", "F5", "DOWNARROW") to a keycode.
// Returns kKeyNone when unrecognised.
uint8_t keycodeForName(const char* name);

// Maps a DuckyScript modifier name ("CTRL", "GUI", "WINDOWS") to its bit.
// Returns 0 when the word is not a modifier.
uint8_t modifierForName(const char* name);

// True when every character in `text` can be typed on this layout.
bool canTypeAll(const char* text, uint16_t len, char* firstBadChar);

}  // namespace orthrus::ducky
