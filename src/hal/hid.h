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

    // Whether the host has enumerated us AND is collecting HID reports.
    //
    // This USED to be a settle timer, with a comment insisting a HID keyboard
    // is one-way and the host never tells us it is listening. That was wrong,
    // and comparing against Dolos -- the same author's hardware-verified BadUSB
    // firmware -- is what showed it: tud_mounted() says the host enumerated us,
    // and tud_hid_n_ready() is false while a report is queued and true again
    // once the HOST HAS POLLED IT. Between them that is a real signal, not a
    // guess, and it is available through the Arduino stack too.
    bool hostReady() const;

    // Keystrokes that could not be delivered because the endpoint never came
    // free. Without this the device reports "200 keys sent" for a payload that
    // typed nothing at all -- which is the worst possible thing for an
    // operator to read off a screen mid-engagement.
    uint32_t keysDropped() const { return keysDropped_; }

    // One chord: modifiers held, key pressed, everything released.
    //
    // Returns false when the host did not take the report. Paced by the host's
    // own polling rather than a fixed delay -- a fixed delay is a guess about a
    // machine we have never met: too short and characters vanish, too long and
    // every payload crawls.
    bool chord(uint8_t modifiers, uint8_t keycode);

    // Types text, resolving each character through the US keymap. Returns the
    // number of characters actually sent; anything untypeable is skipped and
    // the shortfall is visible to the caller rather than silent.
    uint16_t type(const char* text, uint16_t len, uint16_t perKeyMs);

    // Releases everything. Called on the way out of any payload so a crash
    // mid-run cannot leave a modifier stuck down on the host.
    void releaseAll();

    uint32_t keysSent() const { return keysSent_; }

private:
    bool     available_   = false;
    uint32_t keysSent_    = 0;
    uint32_t keysDropped_ = 0;
    uint32_t startedMs_   = 0;
};

Hid& sharedHid();

// Whether this firmware was built with HID support, for the UI to explain
// itself rather than just failing.
bool hidSupportedInBuild();

}  // namespace orthrus::hal
