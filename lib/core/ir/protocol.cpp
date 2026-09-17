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
        case Protocol::Sony15:      return "Sony 15";
        case Protocol::Sony20:      return "Sony 20";
        case Protocol::Rc5:         return "RC5";
    }
    return "?";
}

uint16_t carrierFor(Protocol p) {
    switch (p) {
        case Protocol::Sony12:
        case Protocol::Sony15:
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
        case Protocol::Sony15:      return 0xFF;    // 8 bits
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
        case Protocol::Sony15:
        case Protocol::Sony20:      return 0x7F;  // 7 bits
        case Protocol::Rc5:         return 0x3F;  // 6 bits
    }
    return 0;
}

uint32_t repeatGapUs(Protocol p) {
    switch (p) {
        case Protocol::Sony12:
        case Protocol::Sony15:
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
        case Protocol::Sony15:
        case Protocol::Sony20: {
            const uint8_t cmdBits  = 7;
            const uint8_t addrBits = (p == Protocol::Sony12) ? 5
                                   : (p == Protocol::Sony15) ? 8
                                                             : 13;

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

// ---- decoding ----------------------------------------------------------------

bool within(uint16_t actual, uint16_t expected) {
    uint32_t slack = (static_cast<uint32_t>(expected) * kTolerancePercent) / 100;
    if (slack < kToleranceFloorUs) slack = kToleranceFloorUs;
    const uint32_t lo = expected > slack ? expected - slack : 0;
    const uint32_t hi = static_cast<uint32_t>(expected) + slack;
    return actual >= lo && actual <= hi;
}

namespace {

// NEC and its extended form differ only in whether the address byte is followed
// by its own complement. Both are decoded here and told apart at the end.
bool decodeNecFamily(const PulseTrain& t, Decoded& out) {
    if (t.count < 3) return false;
    if (!within(t.us[0], kNecHeaderMark)) return false;

    // A repeat frame is header, half-length space, stop mark. It carries no
    // data and means the key is still down.
    if (within(t.us[1], 2250) && t.count <= 4) {
        out.protocol = Protocol::Nec;
        out.repeat   = true;
        return true;
    }

    if (!within(t.us[1], kNecHeaderSpace)) return false;
    // Header (2) + 32 bits of mark/space (64) + stop mark (1).
    if (t.count < 2 + 64) return false;

    uint8_t bytes[4] = {0};
    for (int bit = 0; bit < 32; bit++) {
        const uint16_t mark  = t.us[2 + bit * 2];
        const uint16_t space = t.us[3 + bit * 2];
        if (!within(mark, kNecBitMark)) return false;

        bool one;
        if (within(space, kNecOneSpace))       one = true;
        else if (within(space, kNecZeroSpace)) one = false;
        else return false;

        // Least significant bit first, within each byte in turn.
        if (one) bytes[bit / 8] = static_cast<uint8_t>(bytes[bit / 8] | (1 << (bit % 8)));
    }

    out.command = bytes[2];
    // The command byte always carries its own complement. If that does not
    // check out the capture is corrupt, and saying so beats storing a button
    // that will never work.
    if (static_cast<uint8_t>(bytes[2] ^ bytes[3]) != 0xFF) return false;

    if (static_cast<uint8_t>(bytes[0] ^ bytes[1]) == 0xFF) {
        out.protocol = Protocol::Nec;
        out.address  = bytes[0];
    } else {
        // No complement on the address: the two bytes ARE the address.
        out.protocol = Protocol::NecExtended;
        out.address  = static_cast<uint16_t>(bytes[0] | (bytes[1] << 8));
    }
    return true;
}

bool decodeSonyFamily(const PulseTrain& t, Decoded& out) {
    if (t.count < 4) return false;
    if (!within(t.us[0], kSonyHeaderMark)) return false;
    if (!within(t.us[1], kSonySpace)) return false;

    // SIRC frames are 12, 15 or 20 bits, and the width has to be decided by an
    // EXACT count, never a range.
    //
    // An earlier version tested `count >= 25` for twelve bits, which meant a
    // real 15-bit frame (count 32) decoded as a 12-bit one with its top three
    // address bits silently dropped -- a successful decode of the wrong
    // address. That is precisely the failure this decoder claims to avoid, so
    // the widths are now matched exactly, with the single documented allowance
    // that the trailing space may be missing because a receiver stops at the
    // last mark.
    static const uint8_t kSircWidths[3] = {12, 15, 20};
    uint8_t bits = 0;
    for (uint8_t candidate : kSircWidths) {
        const size_t full = 2 + static_cast<size_t>(candidate) * 2;
        if (t.count == full || t.count == full - 1) {
            bits = candidate;
            break;
        }
    }
    if (bits == 0) return false;

    uint32_t value = 0;
    for (uint8_t i = 0; i < bits; i++) {
        const size_t markAt = 2 + static_cast<size_t>(i) * 2;
        if (markAt >= t.count) return false;
        const uint16_t mark = t.us[markAt];

        bool one;
        if (within(mark, kSonyOneMark))       one = true;
        else if (within(mark, kSonyZeroMark)) one = false;
        else return false;
        if (one) value |= (1u << i);

        // The trailing space is checked when present and forgiven when the
        // capture ended on the mark.
        const size_t spaceAt = markAt + 1;
        if (spaceAt < t.count && !within(t.us[spaceAt], kSonySpace)) return false;
    }

    out.command = static_cast<uint16_t>(value & 0x7F);
    if (bits == 12) {
        out.protocol = Protocol::Sony12;
        out.address  = static_cast<uint16_t>((value >> 7) & 0x1F);
    } else if (bits == 15) {
        out.protocol = Protocol::Sony15;
        out.address  = static_cast<uint16_t>((value >> 7) & 0xFF);
    } else {
        out.protocol = Protocol::Sony20;
        out.address  = static_cast<uint16_t>((value >> 7) & 0x1FFF);
    }
    return true;
}

bool decodeRc5(const PulseTrain& t, Decoded& out) {
    if (t.count < 10) return false;

    // Expand the merged runs back into half-bit levels. The encoder merged
    // equal neighbours to produce 1778 us intervals; this undoes exactly that.
    bool level[32];
    int n = 0;
    bool mark = true;   // a train always begins with a mark
    for (uint8_t i = 0; i < t.count; i++) {
        int halves;
        if (within(t.us[i], kRc5Half))          halves = 1;
        else if (within(t.us[i], kRc5Half * 2)) halves = 2;
        else return false;

        for (int k = 0; k < halves; k++) {
            if (n >= 32) return false;
            level[n++] = mark;
        }
        mark = !mark;
    }

    // The first start bit is a one, encoded space-then-mark -- so its leading
    // space is silence and never reaches us. Put it back.
    bool halves[32];
    int total = 0;
    halves[total++] = false;
    for (int i = 0; i < n && total < 32; i++) halves[total++] = level[i];

    // And the mirror of that at the other end: a frame whose final half-bit is
    // a SPACE ends on silence, which a receiver does not record either. Without
    // this, every RC5 command with a zero in the last bit position -- half of
    // all of them -- arrives one half-bit short and decodes as nothing.
    if (total == 27) {
        // Split across two statements deliberately: writing this as
        // halves[total++] = !halves[total - 1] reads the index on both sides of
        // a post-increment with no sequence point between them, which is
        // undefined. Host clang happened to evaluate it the intended way and
        // the tests passed; the Xtensa compiler flagged it.
        halves[total] = !halves[total - 1];
        total++;
    }

    // 14 bits, two half-bits each.
    if (total < 28) return false;

    uint16_t bits = 0;
    for (int i = 0; i < 14; i++) {
        const bool first  = halves[i * 2];
        const bool second = halves[i * 2 + 1];
        if (first == second) return false;   // not Manchester at all
        bits = static_cast<uint16_t>((bits << 1) | (second ? 1 : 0));
    }

    // Two start bits, then toggle, address, command.
    if (((bits >> 13) & 1) != 1) return false;

    // The SECOND start bit is not a constant. In RC5X it carries the inverted
    // seventh command bit, so a frame with it clear is an extended command in
    // 64..127 -- and reading it as plain RC5 reports a command exactly 64 too
    // low, which replays as a different button on the target.
    //
    // This encoder only emits plain RC5, so an RC5X frame is refused rather
    // than decoded into something that cannot be re-encoded faithfully. The
    // capture is still replayable verbatim, which is byte-exact.
    if (((bits >> 12) & 1) != 1) return false;

    out.protocol = Protocol::Rc5;
    out.toggle   = ((bits >> 11) & 1) != 0;
    out.address  = static_cast<uint16_t>((bits >> 6) & 0x1F);
    out.command  = static_cast<uint16_t>(bits & 0x3F);
    return true;
}

}  // namespace

bool decode(const PulseTrain& t, Decoded& out) {
    out = Decoded{};
    if (t.count < 3) return false;

    // Ordered by how distinctive the header is. NEC's 9 ms mark and Sony's
    // 2.4 ms one cannot be mistaken for each other or for RC5, which has no
    // header at all -- so RC5 is tried last, as the thing left over.
    if (decodeNecFamily(t, out)) return true;

    out = Decoded{};
    if (decodeSonyFamily(t, out)) return true;

    out = Decoded{};
    if (decodeRc5(t, out)) return true;

    out = Decoded{};
    return false;
}

}  // namespace orthrus::ir
