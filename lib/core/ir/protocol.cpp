#include "protocol.h"

namespace orthrus::ir {
namespace {

// NEC: 9 ms header mark, 4.5 ms space, then 32 bits. A bit is a 560 us mark
// followed by 560 us (zero) or 1690 us (one). Frame closes with a stop mark.
constexpr uint16_t kNecHeaderMark  = 9000;
constexpr uint16_t kNecHeaderSpace = 4500;
constexpr uint16_t kNecBitMark     = 560;
constexpr uint16_t kNecZeroSpace   = 560;
constexpr uint16_t kNecOneSpace    = 1690;

// Sony SIRC: 2.4 ms header mark, 600 us space, then bits LSB first. A one is a
// 1.2 ms mark, a zero 600 us, each followed by a 600 us space.
constexpr uint16_t kSonyHeaderMark = 2400;
constexpr uint16_t kSonySpace      = 600;
constexpr uint16_t kSonyOneMark    = 1200;
constexpr uint16_t kSonyZeroMark   = 600;

// RC5: Manchester, one half-bit is 889 us.
constexpr uint16_t kRc5Half = 889;

void push(PulseTrain& t, uint16_t us) {
    if (t.count < kMaxPulses) t.us[t.count++] = us;
}

// NEC sends each byte least-significant bit first.
void necByte(PulseTrain& t, uint8_t b) {
    for (int i = 0; i < 8; i++) {
        push(t, kNecBitMark);
        push(t, (b & (1 << i)) ? kNecOneSpace : kNecZeroSpace);
    }
}

}  // namespace

uint32_t PulseTrain::durationUs() const {
    uint32_t total = 0;
    for (uint8_t i = 0; i < count; i++) total += us[i];
    return total;
}

const char* protocolName(Protocol p) {
    switch (p) {
        case Protocol::Nec:         return "NEC";
        case Protocol::NecExtended: return "NEC ext";
        case Protocol::Sony12:      return "Sony 12";
        case Protocol::Sony20:      return "Sony 20";
        case Protocol::Rc5:         return "RC5";
    }
    return "?";
}

uint16_t carrierFor(Protocol p) {
    switch (p) {
        case Protocol::Sony12:
        case Protocol::Sony20: return 40000;
        case Protocol::Rc5:    return 36000;
        default:               return 38000;
    }
}

uint16_t maxAddress(Protocol p) {
    switch (p) {
        case Protocol::Nec:         return 0xFF;
        case Protocol::NecExtended: return 0xFFFF;
        case Protocol::Sony12:      return 0x1F;    // 5 bits
        case Protocol::Sony20:      return 0x1FFF;  // 13 bits
        case Protocol::Rc5:         return 0x1F;    // 5 bits
    }
    return 0;
}

uint16_t maxCommand(Protocol p) {
    switch (p) {
        case Protocol::Nec:
        case Protocol::NecExtended: return 0xFF;
        case Protocol::Sony12:
        case Protocol::Sony20:      return 0x7F;  // 7 bits
        case Protocol::Rc5:         return 0x3F;  // 6 bits
    }
    return 0;
}

uint32_t repeatGapUs(Protocol p) {
    switch (p) {
        case Protocol::Sony12:
        case Protocol::Sony20: return 45000;  // SIRC frames repeat every 45 ms
        case Protocol::Rc5:    return 114000;
        default:               return 40000;  // NEC repeats every ~110 ms total
    }
}

bool encode(Protocol p, uint16_t address, uint16_t command, PulseTrain& out,
            bool toggle) {
    out = PulseTrain{};
    out.carrierHz = carrierFor(p);

    if (address > maxAddress(p) || command > maxCommand(p)) return false;

    switch (p) {
        case Protocol::Nec: {
            push(out, kNecHeaderMark);
            push(out, kNecHeaderSpace);
            const uint8_t a = static_cast<uint8_t>(address);
            const uint8_t c = static_cast<uint8_t>(command);
            necByte(out, a);
            necByte(out, static_cast<uint8_t>(~a));
            necByte(out, c);
            necByte(out, static_cast<uint8_t>(~c));
            push(out, kNecBitMark);  // stop mark
            return true;
        }

        case Protocol::NecExtended: {
            // The 16-bit address replaces the address-plus-inverse pair, which
            // is what "extended" means: the receiver loses that check.
            push(out, kNecHeaderMark);
            push(out, kNecHeaderSpace);
            necByte(out, static_cast<uint8_t>(address & 0xFF));
            necByte(out, static_cast<uint8_t>(address >> 8));
            const uint8_t c = static_cast<uint8_t>(command);
            necByte(out, c);
            necByte(out, static_cast<uint8_t>(~c));
            push(out, kNecBitMark);
            return true;
        }

        case Protocol::Sony12:
        case Protocol::Sony20: {
            const uint8_t cmdBits  = 7;
            const uint8_t addrBits = (p == Protocol::Sony12) ? 5 : 13;

            push(out, kSonyHeaderMark);
            push(out, kSonySpace);
            for (uint8_t i = 0; i < cmdBits; i++) {
                push(out, (command & (1 << i)) ? kSonyOneMark : kSonyZeroMark);
                push(out, kSonySpace);
            }
            for (uint8_t i = 0; i < addrBits; i++) {
                push(out, (address & (1 << i)) ? kSonyOneMark : kSonyZeroMark);
                push(out, kSonySpace);
            }
            return true;
        }

        case Protocol::Rc5: {
            // Two start bits, a toggle bit, 5 address bits, 6 command bits.
            const uint16_t bits = static_cast<uint16_t>(
                (1u << 13) |                            // start 1
                (1u << 12) |                            // start 2 (RC5, not RC5X)
                (static_cast<unsigned>(toggle) << 11) | // new press vs held
                ((address & 0x1F) << 6) |
                (command & 0x3F));

            // Manchester, expanded to half-bit LEVELS first.
            //
            // An earlier version pushed two 889 us intervals for both a one and
            // a zero, which made them byte-for-byte identical -- RC5 encoded
            // nothing at all, and every frame was the same regardless of the
            // command. Levels have to be built, then equal neighbours merged,
            // which is what produces the 1778 us intervals real RC5 contains.
            //
            // RC5 sends a one as space-then-mark and a zero as mark-then-space.
            bool level[28];
            int  n = 0;
            for (int i = 13; i >= 0; i--) {
                const bool one = (bits >> i) & 1;
                level[n++] = !one;  // first half
                level[n++] = one;   // second half
            }

            // The train must begin with a mark. A leading space is simply
            // silence before the frame and carries nothing.
            int start = 0;
            while (start < n && !level[start]) start++;

            // Merge runs of equal level into one interval each. By
            // construction the result then alternates mark, space, mark...
            int i = start;
            while (i < n) {
                int run = 1;
                while (i + run < n && level[i + run] == level[i]) run++;
                push(out, static_cast<uint16_t>(kRc5Half * run));
                i += run;
            }
            return true;
        }
    }
    return false;
}

}  // namespace orthrus::ir
