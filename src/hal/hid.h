// USB HID keyboard, on the ESP32-S3's native USB.
//
// Reports are built by hand rather than going through the Arduino keyboard
// helper's ASCII layer: the parser has already decided the exact modifier and
// usage code, and a second translation in the middle is one more place for a
// payload to become something the operator did not write.
//
// This needs ARDUINO_USB_MODE=0 (TinyUSB). Under mode 1 the chip presents the
// hardware USB-Serial-JTAG instead and there is no HID at all, so the whole
// class compiles to a stub that reports itself unavailable -- which is better
// than a build error for anyone who flips the mode back.

#pragma once

#include <cstdint>

namespace orthrus::hal {

class Hid {
public:
    // Brings up the USB stack. The host needs a moment to enumerate before any
    // keystroke will land, which is why `settleMs` exists and defaults to
    // something generous.
    bool begin();

    // True when the build supports HID at all, and the stack came up.
    bool available() const { return available_; }

    // Whether enough time has passed since bring-up for a typical host to
    // have enumerated.
    //
    // NOT a handshake. A HID keyboard is one-way: the host never tells us it
    // is listening, so this is a settle timer and the UI wording says so
    // rather than claiming a confirmation we cannot get.
    bool hostReady() const;

    // One chord: modifiers held, key pressed, everything released.
    void chord(uint8_t modifiers, uint8_t keycode);

    // Types text, resolving each character through the US keymap. Returns the
    // number of characters actually sent; anything untypeable is skipped and
    // the shortfall is visible to the caller rather than silent.
    uint16_t type(const char* text, uint16_t len, uint16_t perKeyMs);

    // Releases everything. Called on the way out of any payload so a crash
    // mid-run cannot leave a modifier stuck down on the host.
    void releaseAll();

    uint32_t keysSent() const { return keysSent_; }

private:
    bool     available_ = false;
    uint32_t keysSent_  = 0;
    uint32_t startedMs_ = 0;
};

Hid& sharedHid();

// Whether this firmware was built with HID support, for the UI to explain
// itself rather than just failing.
bool hidSupportedInBuild();

}  // namespace orthrus::hal
