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
bool encode(Protocol p, uint16_t address, uint16_t command, PulseTrain& out);

// The gap a remote leaves between repeats of the same frame.
uint32_t repeatGapUs(Protocol p);

const char* protocolName(Protocol p);
uint16_t    carrierFor(Protocol p);

// Widest address and command each protocol can carry, for input validation.
uint16_t maxAddress(Protocol p);
uint16_t maxCommand(Protocol p);

}  // namespace orthrus::ir
