#include "hid.h"

#include <Arduino.h>

#include "ducky/keymap.h"

#if !ARDUINO_USB_MODE
#include <USB.h>
#include <USBHIDKeyboard.h>
// For tud_mounted() / tud_hid_n_ready(). These are what the Arduino USBHID
// class itself calls; going straight to them avoids constructing a second
// USBHID object, which would register another interface descriptor.
#include "tusb.h"
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
    // A real signal now, not a settle timer.
    //
    // tud_mounted() is true once the host has enumerated us, and
    // tud_hid_n_ready() is true when the HID endpoint is free -- it goes false
    // while a report is queued and true again once the host has POLLED it. A
    // host that is not collecting reports leaves it false, which is exactly the
    // condition we want to refuse to fire into.
    if (!available_) return false;
    return tud_mounted() && tud_hid_n_ready(0);
}

namespace {

// Waits for the HID endpoint to come free. Well past any real poll interval --
// a host polls a keyboard every 1 to 10 ms, so anything approaching this is a
// host that has stopped listening rather than a slow one.
constexpr uint32_t kEndpointWaitMs = 300;

bool waitForEndpoint() {
    const uint32_t start = millis();
    while (!tud_hid_n_ready(0)) {
        if (!tud_mounted()) return false;
        if (millis() - start > kEndpointWaitMs) return false;
        delay(1);
    }
    return true;
}

}  // namespace

bool Hid::chord(uint8_t modifiers, uint8_t keycode) {
    if (!available_) return false;

    // Paced by the host, not by a guess.
    //
    // A fixed delay between keystrokes is a guess about a machine we have never
    // met: too short and characters vanish, too long and every payload crawls.
    // The USB stack already knows the answer -- the endpoint is busy while a
    // report is queued and free again once the host has collected it, so
    // waiting on that edge runs at exactly the host's own rate.
    //
    // Arduino's USBHIDKeyboard::sendReport() already blocks on the completion
    // callback internally, but it DISCARDS the result, so a report the host
    // never took is indistinguishable from one it did. Bracketing the send with
    // an explicit endpoint check is what lets this report a drop instead of
    // silently over-counting.
    if (!waitForEndpoint()) {
        keysDropped_++;
        return false;
    }

    // KeyReport is the raw HID layout: modifier byte, a reserved byte, then up
    // to six simultaneous usage codes. Sending it directly means the exact
    // bytes the parser decided on reach the host.
    KeyReport report = {};
    report.modifiers = modifiers;
    report.keys[0]   = keycode;
    g_keyboard.sendReport(&report);

    // The press has to be COLLECTED before the release is queued, or a host
    // that polls slowly sees the key appear and vanish inside one interval and
    // registers nothing.
    if (!waitForEndpoint()) {
        keysDropped_++;
        return false;
    }

    KeyReport release = {};
    g_keyboard.sendReport(&release);
    if (!waitForEndpoint()) {
        keysDropped_++;
        return false;
    }

    keysSent_++;
    return true;
}

uint16_t Hid::type(const char* text, uint16_t len, uint16_t perKeyMs) {
    if (!available_ || text == nullptr) return 0;

    uint16_t sent = 0;
    for (uint16_t i = 0; i < len && text[i]; i++) {
        const ducky::KeyStroke k = ducky::keyForChar(text[i]);
        if (!k.valid()) continue;  // reported by the caller, not guessed at
        // Stop on the first drop rather than typing the REST of a payload into
        // a host that missed the middle of it -- half a command line is worse
        // than none.
        if (!chord(k.modifiers, k.keycode)) break;
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
bool     Hid::chord(uint8_t, uint8_t) { return false; }
uint16_t Hid::type(const char*, uint16_t, uint16_t) { return 0; }
void     Hid::releaseAll() {}

#endif

Hid& sharedHid() {
    static Hid instance;
    return instance;
}

}  // namespace orthrus::hal
