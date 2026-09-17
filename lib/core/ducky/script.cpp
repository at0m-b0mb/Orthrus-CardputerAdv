#include "script.h"

#include <cstdio>
#include <cstring>

namespace orthrus::ducky {
namespace {

bool isSpace(char c) { return c == ' ' || c == '\t'; }

const char* skipSpaces(const char* p) {
    while (*p && isSpace(*p)) p++;
    return p;
}

// Copies the next whitespace-delimited word, both verbatim and uppercased.
//
// Both forms are needed: keywords are matched case-insensitively, but a
// single-character key must keep its case, because GUI R and GUI r are
// different keystrokes to the host.
const char* takeWord(const char* p, char* raw, char* upper, size_t cap) {
    size_t n = 0;
    while (*p && !isSpace(*p) && *p != '\r' && *p != '\n') {
        if (n + 1 < cap) {
            raw[n] = *p;
            char c = *p;
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
            upper[n] = c;
            n++;
        }
        p++;
    }
    raw[n]   = '\0';
    upper[n] = '\0';
    return p;
}

bool equals(const char* a, const char* b) { return std::strcmp(a, b) == 0; }

// Parses an unsigned decimal. Returns false on anything that is not entirely
// digits, so "DELAY abc" is an error rather than a silent zero -- a payload
// that races ahead because a delay parsed as nothing is very hard to debug.
bool parseNumber(const char* p, uint32_t& out) {
    p = skipSpaces(p);
    if (*p < '0' || *p > '9') return false;

    uint32_t v = 0;
    bool     saturated = false;
    for (; *p >= '0' && *p <= '9'; p++) {
        const uint32_t digit = static_cast<uint32_t>(*p - '0');
        // Clamp rather than wrap. A delay of four billion milliseconds is
        // certainly a typo, but wrapping it to a tiny number would run the
        // payload at full speed against a machine that was not ready.
        //
        // The loop keeps consuming digits after saturating rather than
        // breaking: leaving the cursor mid-number made the trailing-garbage
        // check below reject the whole line, so an over-long delay became a
        // parse error instead of a clamped one.
        if (saturated || v > (0xFFFFFFFFu - digit) / 10u) {
            saturated = true;
            v = 0xFFFFFFFFu;
            continue;
        }
        v = v * 10u + digit;
    }
    p = skipSpaces(p);
    if (*p != '\0' && *p != '\r' && *p != '\n') return false;

    out = v;
    return true;
}

// Trims the trailing newline from a string payload without copying it.
uint16_t visibleLength(const char* p) {
    uint16_t n = 0;
    while (p[n] && p[n] != '\r' && p[n] != '\n') n++;
    return n;
}

}  // namespace

const char* lineKindName(LineKind k) {
    switch (k) {
        case LineKind::Empty:        return "empty";
        case LineKind::Comment:      return "comment";
        case LineKind::Delay:        return "delay";
        case LineKind::DefaultDelay: return "default delay";
        case LineKind::String:       return "string";
        case LineKind::StringLn:     return "string line";
        case LineKind::Keys:         return "keys";
        case LineKind::Repeat:       return "repeat";
        case LineKind::Unknown:      return "unknown";
    }
    return "?";
}

void parseLine(const char* line, ParsedLine& out) {
    out = ParsedLine{};
    if (line == nullptr) return;

    const char* p = skipSpaces(line);
    if (*p == '\0' || *p == '\r' || *p == '\n') {
        out.kind = LineKind::Empty;
        return;
    }

    char wordRaw[kMaxWordLen];
    char word[kMaxWordLen];
    const char* afterFirst = takeWord(p, wordRaw, word, sizeof(word));

    if (equals(word, "REM") || word[0] == '#') {
        out.kind = LineKind::Comment;
        return;
    }

    // STRING keeps its argument verbatim, including case and leading spaces
    // after the single separating space. Uppercasing a password would be a
    // memorable bug.
    if (equals(word, "STRING") || equals(word, "STRINGLN")) {
        out.kind = equals(word, "STRING") ? LineKind::String : LineKind::StringLn;
        const char* text = afterFirst;
        if (*text == ' ' || *text == '\t') text++;  // exactly one separator
        out.text    = text;
        out.textLen = visibleLength(text);
        return;
    }

    if (equals(word, "DELAY")) {
        if (parseNumber(afterFirst, out.number)) out.kind = LineKind::Delay;
        else {
            out.kind = LineKind::Unknown;
            std::snprintf(out.unknownWord, kMaxWordLen, "DELAY?");
        }
        return;
    }

    if (equals(word, "DEFAULTDELAY") || equals(word, "DEFAULT_DELAY")) {
        if (parseNumber(afterFirst, out.number)) out.kind = LineKind::DefaultDelay;
        else {
            out.kind = LineKind::Unknown;
            std::snprintf(out.unknownWord, kMaxWordLen, "DEFAULTDELAY?");
        }
        return;
    }

    if (equals(word, "REPEAT")) {
        if (parseNumber(afterFirst, out.number)) out.kind = LineKind::Repeat;
        else {
            out.kind = LineKind::Unknown;
            std::snprintf(out.unknownWord, kMaxWordLen, "REPEAT?");
        }
        return;
    }

    // Otherwise: a sequence of modifiers ending in at most one real key.
    // "CTRL ALT DELETE", "GUI r", "ENTER".
    uint8_t modifiers = 0;
    uint8_t keycode   = kKeyNone;

    const char* cursor = p;
    char        raw[kMaxWordLen];
    char        token[kMaxWordLen];

    while (*cursor) {
        cursor = takeWord(cursor, raw, token, sizeof(token));
        if (token[0] == '\0') break;

        const uint8_t mod = modifierForName(token);
        if (mod != 0 && keycode == kKeyNone) {
            modifiers |= mod;
            cursor = skipSpaces(cursor);
            continue;
        }

        // A one-character token is a literal key and keeps its own case; a
        // longer one is a named key like ENTER or F5.
        uint8_t k = kKeyNone;
        if (raw[1] == '\0') {
            const KeyStroke ks = keyForChar(raw[0]);
            k = ks.keycode;
            modifiers |= ks.modifiers;   // 'R' carries its own shift
        } else {
            k = keycodeForName(token);
        }

        if (k == kKeyNone) {
            out.kind = LineKind::Unknown;
            std::snprintf(out.unknownWord, kMaxWordLen, "%s", raw);
            return;
        }
        if (keycode != kKeyNone) {
            // Two real keys on one line is not a chord the host can receive.
            out.kind = LineKind::Unknown;
            std::snprintf(out.unknownWord, kMaxWordLen, "%s", raw);
            return;
        }
        keycode = k;
        cursor  = skipSpaces(cursor);
    }

    if (keycode == kKeyNone && modifiers == 0) {
        out.kind = LineKind::Unknown;
        std::snprintf(out.unknownWord, kMaxWordLen, "%s", wordRaw);
        return;
    }

    out.kind      = LineKind::Keys;
    out.modifiers = modifiers;
    out.keycode   = keycode;
}

}  // namespace orthrus::ducky
