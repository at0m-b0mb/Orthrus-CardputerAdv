#include "keymap.h"

#include <cstring>

namespace orthrus::ducky {
namespace {

// Characters reachable without shift, in HID usage order from 0x1E.
// '1'..'9' then '0'.
constexpr char kDigits[] = "1234567890";

struct Punct {
    char    ch;
    uint8_t usage;
};

// Unshifted punctuation, US layout.
constexpr Punct kPunct[] = {
    {'-', 0x2D}, {'=', 0x2E}, {'[', 0x2F}, {']', 0x30}, {'\\', 0x31},
    {';', 0x33}, {'\'', 0x34}, {'`', 0x35}, {',', 0x36}, {'.', 0x37},
    {'/', 0x38}, {' ', kKeySpace},
};

// Shifted characters and the unshifted key that carries them.
constexpr Punct kShifted[] = {
    {'!', 0x1E}, {'@', 0x1F}, {'#', 0x20}, {'$', 0x21}, {'%', 0x22},
    {'^', 0x23}, {'&', 0x24}, {'*', 0x25}, {'(', 0x26}, {')', 0x27},
    {'_', 0x2D}, {'+', 0x2E}, {'{', 0x2F}, {'}', 0x30}, {'|', 0x31},
    {':', 0x33}, {'"', 0x34}, {'~', 0x35}, {'<', 0x36}, {'>', 0x37},
    {'?', 0x38},
};

struct Named {
    const char* name;
    uint8_t     usage;
};

constexpr Named kNamed[] = {
    {"ENTER", kKeyEnter},          {"RETURN", kKeyEnter},
    {"ESC", kKeyEscape},           {"ESCAPE", kKeyEscape},
    {"BACKSPACE", kKeyBackspace},  {"TAB", kKeyTab},
    {"SPACE", kKeySpace},          {"CAPSLOCK", kKeyCapsLock},
    {"PRINTSCREEN", kKeyPrintScr}, {"SCROLLLOCK", kKeyScrollLock},
    {"PAUSE", kKeyPause},          {"BREAK", kKeyPause},
    {"INSERT", kKeyInsert},        {"HOME", kKeyHome},
    {"PAGEUP", kKeyPageUp},        {"DELETE", kKeyDelete},
    {"DEL", kKeyDelete},           {"END", kKeyEnd},
    {"PAGEDOWN", kKeyPageDown},    {"NUMLOCK", kKeyNumLock},
    {"APP", kKeyApplication},      {"MENU", kKeyApplication},
    {"RIGHT", kKeyRight},          {"RIGHTARROW", kKeyRight},
    {"LEFT", kKeyLeft},            {"LEFTARROW", kKeyLeft},
    {"DOWN", kKeyDown},            {"DOWNARROW", kKeyDown},
    {"UP", kKeyUp},                {"UPARROW", kKeyUp},
};

constexpr Named kModifiers[] = {
    {"CTRL", kModCtrl},       {"CONTROL", kModCtrl},
    {"SHIFT", kModShift},
    {"ALT", kModAlt},         {"OPTION", kModAlt},
    {"GUI", kModGui},         {"WINDOWS", kModGui},
    {"WIN", kModGui},         {"COMMAND", kModGui},
    {"META", kModGui},
};

bool equalsIgnoreCase(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = static_cast<char>(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = static_cast<char>(cb - 32);
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

}  // namespace

KeyStroke keyForChar(char c) {
    KeyStroke k;

    if (c >= 'a' && c <= 'z') {
        k.keycode = static_cast<uint8_t>(kKeyA + (c - 'a'));
        return k;
    }
    if (c >= 'A' && c <= 'Z') {
        k.keycode   = static_cast<uint8_t>(kKeyA + (c - 'A'));
        k.modifiers = kModShift;
        return k;
    }

    for (size_t i = 0; i < sizeof(kDigits) - 1; i++) {
        if (kDigits[i] == c) {
            k.keycode = static_cast<uint8_t>(0x1E + i);
            return k;
        }
    }

    for (const auto& p : kPunct) {
        if (p.ch == c) {
            k.keycode = p.usage;
            return k;
        }
    }
    for (const auto& p : kShifted) {
        if (p.ch == c) {
            k.keycode   = p.usage;
            k.modifiers = kModShift;
            return k;
        }
    }

    // Newline and tab inside a STRING are legitimate; anything else we cannot
    // type is reported rather than approximated.
    if (c == '\n') { k.keycode = kKeyEnter; return k; }
    if (c == '\t') { k.keycode = kKeyTab;   return k; }

    return k;  // invalid
}

uint8_t keycodeForName(const char* name) {
    if (name == nullptr || name[0] == '\0') return kKeyNone;

    for (const auto& n : kNamed)
        if (equalsIgnoreCase(name, n.name)) return n.usage;

    // Function keys F1..F12 are contiguous from 0x3A.
    if ((name[0] == 'F' || name[0] == 'f') && name[1] != '\0') {
        int num = 0;
        for (const char* p = name + 1; *p; p++) {
            if (*p < '0' || *p > '9') return kKeyNone;
            num = num * 10 + (*p - '0');
            if (num > 12) return kKeyNone;
        }
        if (num >= 1 && num <= 12)
            return static_cast<uint8_t>(kKeyF1 + (num - 1));
        return kKeyNone;
    }

    // A single character is a key in its own right: GUI r, CTRL c.
    if (name[1] == '\0') {
        const KeyStroke k = keyForChar(name[0]);
        return k.keycode;
    }

    return kKeyNone;
}

uint8_t modifierForName(const char* name) {
    if (name == nullptr) return 0;
    for (const auto& m : kModifiers)
        if (equalsIgnoreCase(name, m.name)) return m.usage;
    return 0;
}

bool canTypeAll(const char* text, uint16_t len, char* firstBadChar) {
    if (firstBadChar) *firstBadChar = '\0';
    if (text == nullptr) return true;

    for (uint16_t i = 0; i < len && text[i]; i++) {
        if (!keyForChar(text[i]).valid()) {
            if (firstBadChar) *firstBadChar = text[i];
            return false;
        }
    }
    return true;
}

}  // namespace orthrus::ducky
