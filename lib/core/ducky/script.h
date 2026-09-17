// DuckyScript parsing.
//
// One line at a time, into a decided action. Pure: no USB, no timers, no file
// I/O, so the whole language can be exercised on a host. That matters because
// the failure mode of a parser bug here is not a crash -- it is typing
// something other than what the operator wrote, into a machine that is not
// theirs.
//
// Supported: REM, DELAY, DEFAULTDELAY, STRING, STRINGLN, REPEAT, key names,
// and modifier combinations. Anything unrecognised is reported AS unrecognised
// and carries the offending word, because a payload that silently skips a line
// it did not understand is a payload that half-runs.

#pragma once

#include <cstddef>
#include <cstdint>

#include "keymap.h"

namespace orthrus::ducky {

enum class LineKind : uint8_t {
    Empty = 0,
    Comment,        // REM ...
    Delay,          // DELAY <ms>
    DefaultDelay,   // DEFAULTDELAY <ms> / DEFAULT_DELAY <ms>
    String,         // STRING <text>
    StringLn,       // STRINGLN <text> -- types the text then presses Enter
    Keys,           // a key, optionally with modifiers
    Repeat,         // REPEAT <n> -- repeats the PREVIOUS line
    Unknown,        // recognised as a line, but not as anything we can run
};

inline constexpr size_t kMaxWordLen = 24;

struct ParsedLine {
    LineKind kind = LineKind::Empty;

    uint32_t number = 0;       // Delay, DefaultDelay, Repeat

    uint8_t modifiers = 0;     // Keys
    uint8_t keycode   = kKeyNone;

    // String / StringLn. Points INTO the line passed to parseLine, so the
    // caller's buffer must outlive the result. Nothing is copied: on a device
    // with no PSRAM, a parser that duplicates every string is a parser that
    // eventually stops working.
    const char* text   = nullptr;
    uint16_t    textLen = 0;

    // Unknown: the word we could not place, for an error the operator can act
    // on. "Line 14: WINKEY" beats "parse error".
    char unknownWord[kMaxWordLen] = {0};
};

// Parses one line. Always succeeds in the sense that it always classifies the
// line; `kind` says what it decided.
void parseLine(const char* line, ParsedLine& out);

// True for lines that do nothing when run.
inline bool isNoop(LineKind k) {
    return k == LineKind::Empty || k == LineKind::Comment;
}

const char* lineKindName(LineKind k);

}  // namespace orthrus::ducky
