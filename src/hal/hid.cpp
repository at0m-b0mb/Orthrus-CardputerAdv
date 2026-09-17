#include "hid.h"

#include <Arduino.h>

#include "ducky/keymap.h"

#if !ARDUINO_USB_MODE
#include <USB.h>
#include <USBHIDKeyboard.h>
#endif

namespace orthrus::hal {

#if !ARDUINO_USB_MODE

namespace {
USBHIDKeyboard g_keyboard;
bool           g_started = false;
}  // namespace

bool hidSupportedInBuild() { return true; }

bool Hid::begin() {
    if (available_) return true;
    if (!g_started) {
        g_keyboard.begin();
        USB.begin();
        g_started = true;
        startedMs_ = millis();
        // Enumeration is not instant and the host will drop anything sent
        // before it finishes. This is not the full wait -- hostReady() is --
        // but it covers the common case of entering the screen and firing.
        delay(600);
    }
    available_ = true;
    return true;
}

bool Hid::hostReady() const {
    // Honest limitation: a HID keyboard is a one-way device. The host never
    // tells us it is listening, and TinyUSB's mount state is not exposed
    // through the Arduino layer here, so this is a settle timer rather than a
    // real handshake. It reports that enough time has passed for a typical
    // host to enumerate -- not that one actually did.
    if (!available_) return false;
    return (millis() - startedMs_) > 1200;
}

void Hid::chord(uint8_t modifiers, uint8_t keycode) {
    if (!available_) return;

    // KeyReport is the raw HID layout: modifier byte, a reserved byte, then up
    // to six simultaneous usage codes. Sending it directly means the exact
    // bytes the parser decided on reach the host.
    KeyReport report = {};
    report.modifiers = modifiers;
    report.keys[0]   = keycode;

    g_keyboard.sendReport(&report);
    delay(6);   // hosts drop chords that appear and vanish within one poll

    KeyReport release = {};
    g_keyboard.sendReport(&release);
    delay(6);

    keysSent_++;
}

uint16_t Hid::type(const char* text, uint16_t len, uint16_t perKeyMs) {
    if (!available_ || text == nullptr) return 0;

    uint16_t sent = 0;
    for (uint16_t i = 0; i < len && text[i]; i++) {
        const ducky::KeyStroke k = ducky::keyForChar(text[i]);
        if (!k.valid()) continue;  // reported by the caller, not guessed at
        chord(k.modifiers, k.keycode);
        if (perKeyMs) delay(perKeyMs);
        sent++;
    }
    return sent;
}

void Hid::releaseAll() {
    if (!available_) return;
    KeyReport release = {};
    g_keyboard.sendReport(&release);
}

#else  // ARDUINO_USB_MODE == 1: hardware USB-Serial-JTAG, no TinyUSB, no HID.

bool hidSupportedInBuild() { return false; }

bool Hid::begin() {
    available_ = false;
    return false;
}
bool     Hid::hostReady() const { return false; }
void     Hid::chord(uint8_t, uint8_t) {}
uint16_t Hid::type(const char*, uint16_t, uint16_t) { return 0; }
void     Hid::releaseAll() {}

#endif

Hid& sharedHid() {
    static Hid instance;
    return instance;
}

}  // namespace orthrus::hal
