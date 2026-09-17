// Infrared remote protocols, encoded to raw pulse timings.
//
// Pure: this turns a protocol, address and command into a list of microsecond
// marks and spaces, and nothing else. No GPIO, no timers, no Arduino. That is
// what lets the encoding be tested exhaustively on a host, which matters
// because an IR frame is nothing BUT timing -- a single wrong gap and the
// target silently ignores you, with no error to read.
//
// The Cardputer-Adv has an emitter on G44 and no receiver, so transmit works
// out of the box and capture needs the IR unit on a Grove port. Both halves use
// these same timings.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::ir {

enum class Protocol : uint8_t {
    Nec = 0,       // 38 kHz, 32 bits, address + inverse, command + inverse
    NecExtended,   // 16-bit address, no inverse check on it
    Sony12,        // 40 kHz, 12 bits, 7 command + 5 address
    Sony20,        // 40 kHz, 20 bits
    Rc5,           // 36 kHz, Manchester, 14 bits with a toggle
};

// Longest frame we produce: NEC is header + 32 bits x 2 edges + stop = 68.
// RC5 Manchester is 14 bits x 2 = 28. Sony20 is header + 20 x 2 = 42.
inline constexpr size_t kMaxPulses = 80;

struct PulseTrain {
    // Alternating durations in microseconds, starting with a MARK (carrier on).
    uint16_t us[kMaxPulses] = {0};
    uint8_t  count = 0;
    uint16_t carrierHz = 38000;

    // How long the whole frame takes to send. Needed to space repeats
    // correctly: a remote that sends frames back to back faster than the
    // protocol allows is one most receivers ignore.
    uint32_t durationUs() const;
};

// Encodes one frame. Returns false if the protocol cannot represent the given
// address or command, rather than silently truncating them -- a command that
// does not fit is a caller error worth surfacing.
// `toggle` is the RC5 toggle bit and is ignored by every other protocol. It
// must FLIP between separate key presses: RC5 receivers use it to tell a new
// press from a held key, so sending it constant makes the second press look
// like a continuation of the first and it gets dropped.
bool encode(Protocol p, uint16_t address, uint16_t command, PulseTrain& out,
            bool toggle = false);

// The gap a remote leaves between repeats of the same frame.
uint32_t repeatGapUs(Protocol p);

const char* protocolName(Protocol p);
uint16_t    carrierFor(Protocol p);

// ---- decoding ---------------------------------------------------------------
//
// The mirror of encode(), for a train captured off a real remote.
//
// This is NOT the same job as the encoder run backwards. An encoded frame has
// exact timings; a captured one does not. A receiver module adds its own bias
// -- typically stretching marks and shortening spaces by 50 to 100 us -- and
// the remote's own crystal is a few percent out. A decoder that compares for
// equality decodes nothing that was ever actually transmitted.
//
// So every comparison here is proportional, with a floor for the short
// intervals where a fixed error dominates. See kTolerancePercent.

inline constexpr uint8_t  kTolerancePercent = 30;
inline constexpr uint16_t kToleranceFloorUs = 130;

struct Decoded {
    Protocol protocol = Protocol::Nec;
    uint16_t address  = 0;
    uint16_t command  = 0;
    bool     toggle   = false;   // RC5 only

    // A NEC "repeat" frame: header, short space, stop mark, and no data at all.
    // It means the key is still held. Reporting it as a decode failure makes a
    // held button look like a broken capture.
    bool repeat = false;
};

// True when `actual` is within tolerance of `expected`.
bool within(uint16_t actual, uint16_t expected);

// Identifies a captured train. Returns false when it matches nothing, rather
// than guessing at the closest fit -- a wrong protocol replays as a different
// button, or as nothing.
bool decode(const PulseTrain& t, Decoded& out);

// Widest address and command each protocol can carry, for input validation.
uint16_t maxAddress(Protocol p);
uint16_t maxCommand(Protocol p);

}  // namespace orthrus::ir
