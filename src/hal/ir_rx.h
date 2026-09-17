// Infrared receive, on whichever Grove pin the receiver turns out to be.
//
// The Cardputer-Adv has an emitter on G44 and NO receiver, so capture needs the
// IR unit on the Grove port. board.h records which line is which; this listens
// on BOTH anyway, because a cable plugged in the other way round is a five
// second mistake that would otherwise present as a screen that never reacts.
//
// WHY RMT AND NOT A GPIO INTERRUPT
//
// The obvious implementation -- attach an edge interrupt, timestamp in the
// handler -- does not work reliably on this build, and the reason is worth
// writing down because it is invisible from the source:
//
//   * This framework has `CONFIG_ARDUINO_ISR_IRAM` unset, so the shared GPIO
//     interrupt dispatcher is NOT in IRAM. Marking our own handler IRAM_ATTR
//     buys nothing when the dispatcher ahead of it lives in flash: every edge
//     during an SD write, when the flash cache is off, is simply lost.
//   * The GPIO ISR service is install-once and shared. RadioLib claims it the
//     first time a LoRa surface is opened, so its flags -- not ours -- are what
//     the whole program gets, and there is no upgrading it afterwards.
//   * IrTx busy-waits on esp_timer_get_time() for the length of a frame on the
//     same core as the UI loop. An edge storm from our own emitter, centimetres
//     away, is the worst possible neighbour for that loop.
//
// The RMT peripheral times edges in hardware into its own RAM and hands over a
// finished frame. None of the above can touch it, and it needs no GPIO
// interrupt service at all.
//
// POLARITY IS DISCOVERED, NOT ASSUMED
//
// A TSOP-class receiver idles HIGH and pulls LOW while it hears carrier, so the
// LOW intervals are the marks. That is the expected case for this unit and
// board.h says so -- but an inverted module would produce a train starting with
// a space, which decodes as nothing. So the idle level is read at startup and
// "mark" is defined as whatever the line is NOT at rest.

#pragma once

#include <cstdint>

#include "ir/protocol.h"

namespace orthrus::hal {

class IrRx {
public:
    // A frame has ended when the line has been idle this long. It has to sit
    // above the longest gap INSIDE a frame (NEC's 4.5 ms header space) and
    // below the gap BETWEEN frames (NEC repeats about every 110 ms).
    static constexpr uint32_t kIdleUs = 12000;

    // Shorter than this is noise, not a frame worth decoding.
    static constexpr uint8_t kMinPulses = 6;

    // Claims both candidate lines. Returns false only if neither channel could
    // be allocated at all.
    bool begin(int pinA, int pinB);

    // Releases the RMT channels. Must be called before anything else wants the
    // Grove port back -- the card reader, for one.
    void end();

    bool running() const { return running_; }

    // Call from the loop. Moves anything the hardware has finished into the
    // latch. Returns true when a new train became available.
    bool poll();

    // Moves the latched train out and arms for the next.
    bool take(ir::PulseTrain& out);

    // Which pin produced the last frame, or -1 if nothing has. This is the
    // answer to "is the unit on the right line", and it belongs on screen.
    int activePin() const { return activePin_; }

    // Frames the hardware handed us per pin, decoded or not. A line with
    // frames but nothing decodable is hearing something that is not a remote;
    // both silent means the unit is not on this port.
    uint32_t framesOn(int pin) const;

    uint32_t framesSeen() const { return framesSeen_; }

    // Frames longer than a PulseTrain can hold. Said out loud rather than
    // silently truncated: a clipped frame decodes as nothing and looks exactly
    // like a dead remote.
    uint32_t overruns() const { return overruns_; }

private:
    struct Channel {
        int      pin  = -1;
        void*    rmt  = nullptr;          // rmt_obj_t*, opaque here
        bool     idleLevel = true;
        volatile uint32_t frames = 0;

        // Filled by the RMT callback, drained by poll().
        volatile bool     ready = false;
        volatile uint16_t count = 0;
        uint16_t us[ir::kMaxPulses]    = {0};
        bool     level[ir::kMaxPulses] = {false};
        volatile bool     overflow = false;
    };

    static void onFrame(uint32_t* data, size_t len, void* arg);
    bool assemble(Channel& c);

    Channel  chan_[2];
    bool     running_    = false;
    int      activePin_  = -1;
    uint32_t framesSeen_ = 0;
    uint32_t overruns_   = 0;

    ir::PulseTrain latched_;
    bool           haveLatched_ = false;
};

IrRx& sharedIrRx();

}  // namespace orthrus::hal
