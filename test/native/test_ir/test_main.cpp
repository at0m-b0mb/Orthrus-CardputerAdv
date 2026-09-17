// Host tests for the infrared encoders.
//
// An IR frame is nothing but timing, and a wrong gap fails silently -- the
// target simply ignores you, with no error to read. So the strongest test here
// is a decoder: reconstruct the address and command back out of the pulse train
// and require them to match what went in. If the encoder drifts, that breaks.

#include <unity.h>

#include <cstdio>
#include <cstring>
#include <initializer_list>

#include "ir/protocol.h"

using namespace orthrus::ir;

namespace {

// Reads a NEC train back into its four bytes, the way a receiver would.
bool decodeNec(const PulseTrain& t, uint8_t out[4]) {
    // 2 header + 64 bit intervals + 1 stop mark. The stop mark has no trailing
    // space -- the gap after a frame is just silence -- so it is 67, not 68.
    if (t.count != 67) return false;
    if (t.us[0] != 9000 || t.us[1] != 4500) return false;

    std::memset(out, 0, 4);
    for (int bit = 0; bit < 32; bit++) {
        const uint16_t mark  = t.us[2 + bit * 2];
        const uint16_t space = t.us[3 + bit * 2];
        if (mark != 560) return false;
        const bool one = (space == 1690);
        if (!one && space != 560) return false;
        if (one) out[bit / 8] |= static_cast<uint8_t>(1 << (bit % 8));
    }
    return true;
}

// Reads a Sony train back, command first then address, both LSB first.
bool decodeSony(const PulseTrain& t, uint8_t addrBits, uint16_t& addr,
                uint16_t& cmd) {
    const uint8_t expected = static_cast<uint8_t>(2 + (7 + addrBits) * 2);
    if (t.count != expected) return false;
    if (t.us[0] != 2400 || t.us[1] != 600) return false;

    addr = 0;
    cmd  = 0;
    uint8_t idx = 2;
    for (int i = 0; i < 7; i++, idx += 2) {
        if (t.us[idx + 1] != 600) return false;
        if (t.us[idx] == 1200) cmd |= static_cast<uint16_t>(1u << i);
        else if (t.us[idx] != 600) return false;
    }
    for (int i = 0; i < addrBits; i++, idx += 2) {
        if (t.us[idx + 1] != 600) return false;
        if (t.us[idx] == 1200) addr |= static_cast<uint16_t>(1u << i);
        else if (t.us[idx] != 600) return false;
    }
    return true;
}

// Reads an RC5 train back into its 14 bits, the way a receiver would: expand
// each interval into half-bit levels, restore the implicit leading space, then
// read pairs.
bool decodeRc5(const PulseTrain& t, uint16_t& bits) {
    bool level[32];
    int n = 0;
    bool mark = true;                 // the train always starts on a mark
    level[n++] = false;               // the leading space that was folded away

    for (uint8_t i = 0; i < t.count; i++) {
        if (t.us[i] % 889 != 0) return false;
        const int run = t.us[i] / 889;
        if (run < 1 || run > 2) return false;
        for (int k = 0; k < run; k++) {
            if (n >= 32) return false;
            level[n++] = mark;
        }
        mark = !mark;
    }
    if (n != 28) return false;

    bits = 0;
    for (int b = 0; b < 14; b++) {
        const bool firstHalf  = level[b * 2];
        const bool secondHalf = level[b * 2 + 1];
        if (firstHalf == secondHalf) return false;   // not Manchester
        const bool one = secondHalf;                 // space-then-mark == 1
        bits = static_cast<uint16_t>((bits << 1) | (one ? 1u : 0u));
    }
    return true;
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- NEC --------------------------------------------------------------------

void test_nec_frame_shape_and_header() {
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Nec, 0x04, 0x08, t));
    TEST_ASSERT_EQUAL_UINT8(67, t.count);
    TEST_ASSERT_EQUAL_UINT16(9000, t.us[0]);
    TEST_ASSERT_EQUAL_UINT16(4500, t.us[1]);
    TEST_ASSERT_EQUAL_UINT16(560, t.us[t.count - 1]);  // stop mark
    TEST_ASSERT_EQUAL_UINT16(38000, t.carrierHz);
}

void test_nec_round_trips_through_a_decoder() {
    // The property that matters. Sweep the whole 8-bit space on both fields.
    for (uint16_t addr = 0; addr <= 0xFF; addr += 17) {
        for (uint16_t cmd = 0; cmd <= 0xFF; cmd += 13) {
            PulseTrain t;
            TEST_ASSERT_TRUE(encode(Protocol::Nec, addr, cmd, t));

            uint8_t b[4];
            TEST_ASSERT_TRUE(decodeNec(t, b));
            TEST_ASSERT_EQUAL_UINT8(addr, b[0]);
            TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(~addr), b[1]);
            TEST_ASSERT_EQUAL_UINT8(cmd, b[2]);
            TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(~cmd), b[3]);
        }
    }
}

void test_nec_inverse_bytes_are_genuine_complements() {
    // The inverse pair is the receiver's only integrity check. If it is wrong
    // every frame is rejected and nothing says why.
    PulseTrain t;
    encode(Protocol::Nec, 0x00, 0xFF, t);
    uint8_t b[4];
    TEST_ASSERT_TRUE(decodeNec(t, b));
    TEST_ASSERT_EQUAL_UINT8(0x00, b[0]);
    TEST_ASSERT_EQUAL_UINT8(0xFF, b[1]);
    TEST_ASSERT_EQUAL_UINT8(0xFF, b[2]);
    TEST_ASSERT_EQUAL_UINT8(0x00, b[3]);
}

void test_nec_extended_drops_the_address_check() {
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::NecExtended, 0x1234, 0x56, t));
    uint8_t b[4];
    TEST_ASSERT_TRUE(decodeNec(t, b));
    TEST_ASSERT_EQUAL_UINT8(0x34, b[0]);   // low byte first
    TEST_ASSERT_EQUAL_UINT8(0x12, b[1]);   // high byte, NOT an inverse
    TEST_ASSERT_EQUAL_UINT8(0x56, b[2]);
    TEST_ASSERT_EQUAL_UINT8(0xA9, b[3]);
}

// ---- Sony -------------------------------------------------------------------

void test_sony12_round_trips() {
    for (uint16_t addr = 0; addr <= 0x1F; addr++) {
        for (uint16_t cmd = 0; cmd <= 0x7F; cmd += 7) {
            PulseTrain t;
            TEST_ASSERT_TRUE(encode(Protocol::Sony12, addr, cmd, t));
            uint16_t a = 0, c = 0;
            TEST_ASSERT_TRUE(decodeSony(t, 5, a, c));
            TEST_ASSERT_EQUAL_UINT16(addr, a);
            TEST_ASSERT_EQUAL_UINT16(cmd, c);
        }
    }
}

void test_sony20_round_trips() {
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Sony20, 0x1ABC, 0x55, t));
    uint16_t a = 0, c = 0;
    TEST_ASSERT_TRUE(decodeSony(t, 13, a, c));
    TEST_ASSERT_EQUAL_UINT16(0x1ABC, a);
    TEST_ASSERT_EQUAL_UINT16(0x55, c);
}

void test_sony_uses_a_40khz_carrier() {
    TEST_ASSERT_EQUAL_UINT16(40000, carrierFor(Protocol::Sony12));
    TEST_ASSERT_EQUAL_UINT16(40000, carrierFor(Protocol::Sony20));
    TEST_ASSERT_EQUAL_UINT16(36000, carrierFor(Protocol::Rc5));
    TEST_ASSERT_EQUAL_UINT16(38000, carrierFor(Protocol::Nec));
}

// ---- RC5 --------------------------------------------------------------------

void test_rc5_is_manchester_and_uniform() {
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x05, 0x0A, t));
    TEST_ASSERT_TRUE(t.count > 0);
    // Every RC5 interval is one or two half-bits; nothing else is legal.
    for (uint8_t i = 0; i < t.count; i++) {
        TEST_ASSERT_TRUE(t.us[i] == 889 || t.us[i] == 1778);
    }
}

void test_rc5_round_trips_through_a_decoder() {
    // The property that would have caught the original bug immediately: a one
    // and a zero must encode differently, and the whole word must come back.
    for (uint16_t addr = 0; addr <= 0x1F; addr += 3) {
        for (uint16_t cmd = 0; cmd <= 0x3F; cmd += 5) {
            for (int tog = 0; tog < 2; tog++) {
                PulseTrain t;
                TEST_ASSERT_TRUE(encode(Protocol::Rc5, addr, cmd, t, tog != 0));

                uint16_t bits = 0;
                TEST_ASSERT_TRUE(decodeRc5(t, bits));
                TEST_ASSERT_EQUAL_UINT16(1, (bits >> 13) & 1);      // start 1
                TEST_ASSERT_EQUAL_UINT16(1, (bits >> 12) & 1);      // start 2
                TEST_ASSERT_EQUAL_UINT16(tog, (bits >> 11) & 1);    // toggle
                TEST_ASSERT_EQUAL_UINT16(addr, (bits >> 6) & 0x1F);
                TEST_ASSERT_EQUAL_UINT16(cmd, bits & 0x3F);
            }
        }
    }
}

void test_rc5_contains_double_length_intervals() {
    // Real RC5 merges same-polarity halves. A train of nothing but 889 us
    // intervals is the signature of the encoding bug that was there before.
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x00, 0x00, t, false));
    bool sawLong = false;
    for (uint8_t i = 0; i < t.count; i++) if (t.us[i] == 1778) sawLong = true;
    TEST_ASSERT_TRUE(sawLong);
}

void test_rc5_toggle_bit_actually_changes_the_frame() {
    // The regression. RC5 receivers use the toggle bit to tell a new key press
    // from a held one. Sending it constant makes the second press look like a
    // continuation of the first, and the device ignores it -- a bug that fails
    // silently, since the first press always works.
    PulseTrain a, b;
    TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x05, 0x0A, a, false));
    TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x05, 0x0A, b, true));

    bool differs = false;
    if (a.count != b.count) differs = true;
    else for (uint8_t i = 0; i < a.count; i++)
        if (a.us[i] != b.us[i]) { differs = true; break; }
    TEST_ASSERT_TRUE(differs);
}

void test_toggle_is_ignored_by_every_other_protocol() {
    // Only RC5 carries it. If NEC frames changed with the toggle, a caller
    // flipping it per press would be sending two different commands.
    for (auto p : {Protocol::Nec, Protocol::NecExtended, Protocol::Sony12,
                   Protocol::Sony20}) {
        PulseTrain a, b;
        TEST_ASSERT_TRUE(encode(p, 0x01, 0x02, a, false));
        TEST_ASSERT_TRUE(encode(p, 0x01, 0x02, b, true));
        TEST_ASSERT_EQUAL_UINT8(a.count, b.count);
        for (uint8_t i = 0; i < a.count; i++)
            TEST_ASSERT_EQUAL_UINT16(a.us[i], b.us[i]);
    }
}

void test_toggled_rc5_is_still_valid_manchester() {
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x1F, 0x3F, t, true));
    for (uint8_t i = 0; i < t.count; i++)
        TEST_ASSERT_TRUE(t.us[i] == 889 || t.us[i] == 1778);
}

// ---- range checking ---------------------------------------------------------

void test_out_of_range_is_refused_not_truncated() {
    // Silently masking a command to fit would send a DIFFERENT command, which
    // is far worse than refusing.
    PulseTrain t;
    TEST_ASSERT_FALSE(encode(Protocol::Nec, 0x100, 0x00, t));
    TEST_ASSERT_FALSE(encode(Protocol::Nec, 0x00, 0x100, t));
    TEST_ASSERT_FALSE(encode(Protocol::Sony12, 0x20, 0x00, t));
    TEST_ASSERT_FALSE(encode(Protocol::Sony12, 0x00, 0x80, t));
    TEST_ASSERT_FALSE(encode(Protocol::Rc5, 0x00, 0x40, t));
}

void test_boundary_values_are_accepted() {
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Nec, 0xFF, 0xFF, t));
    TEST_ASSERT_TRUE(encode(Protocol::Sony12, 0x1F, 0x7F, t));
    TEST_ASSERT_TRUE(encode(Protocol::Sony20, 0x1FFF, 0x7F, t));
    TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x1F, 0x3F, t));
    TEST_ASSERT_TRUE(encode(Protocol::NecExtended, 0xFFFF, 0xFF, t));
}

void test_no_train_ever_exceeds_the_buffer() {
    for (int p = 0; p <= static_cast<int>(Protocol::Rc5); p++) {
        const auto proto = static_cast<Protocol>(p);
        PulseTrain t;
        encode(proto, maxAddress(proto), maxCommand(proto), t);
        TEST_ASSERT_TRUE(t.count <= kMaxPulses);
    }
}

// ---- timing sanity ----------------------------------------------------------

void test_frame_duration_is_plausible() {
    // A NEC frame is about 67.5 ms. Wildly off means the timings are wrong in
    // a way the round-trip decoder would not catch.
    PulseTrain t;
    encode(Protocol::Nec, 0x00, 0x00, t);
    const uint32_t d = t.durationUs();
    TEST_ASSERT_TRUE(d > 25000 && d < 80000);
}

void test_repeat_gaps_present_for_every_protocol() {
    for (int p = 0; p <= static_cast<int>(Protocol::Rc5); p++) {
        TEST_ASSERT_TRUE(repeatGapUs(static_cast<Protocol>(p)) > 1000);
        TEST_ASSERT_TRUE(std::strlen(protocolName(static_cast<Protocol>(p))) > 0);
    }
}

// ---- the shipped decoder, against jitter ------------------------------------
//
// The decoders above work on ideal timings and exist to prove the ENCODER. The
// one in lib/core has a harder job: a train captured off a real remote is never
// exact. The receiver module stretches marks and shortens spaces, and the
// remote's own crystal is a few percent out.

namespace {

// Applies a proportional skew plus a fixed bias, the way a receiver does.
PulseTrain skewTrain(const PulseTrain& in, int percent, int biasUs) {
    PulseTrain out = in;
    for (uint8_t i = 0; i < out.count; i++) {
        long v = out.us[i];
        v = v + (v * percent) / 100;
        // Marks are the even indices; a receiver lengthens them and shortens
        // the spaces by the same amount.
        v += (i % 2 == 0) ? biasUs : -biasUs;
        if (v < 1) v = 1;
        out.us[i] = static_cast<uint16_t>(v);
    }
    return out;
}

}  // namespace

void test_every_protocol_survives_encode_then_decode() {
    struct Case { Protocol p; uint16_t addr; uint16_t cmd; };
    const Case cases[] = {
        {Protocol::Nec, 0x04, 0x08},
        {Protocol::Nec, 0x00, 0xFF},
        // 0x34 ^ 0x12 != 0xFF, so this one is unambiguously extended.
        // See the test below for the case where it is not.
        {Protocol::NecExtended, 0x1234, 0x12},
        {Protocol::Sony12, 0x01, 0x15},
        {Protocol::Sony20, 0x1A2B, 0x7F},
        {Protocol::Rc5, 0x05, 0x35},
    };

    for (const auto& c : cases) {
        PulseTrain t;
        TEST_ASSERT_TRUE(encode(c.p, c.addr, c.cmd, t));

        Decoded d;
        TEST_ASSERT_TRUE(decode(t, d));
        TEST_ASSERT_EQUAL(static_cast<int>(c.p), static_cast<int>(d.protocol));
        TEST_ASSERT_EQUAL_UINT16(c.addr, d.address);
        TEST_ASSERT_EQUAL_UINT16(c.cmd, d.command);
        TEST_ASSERT_FALSE(d.repeat);
    }
}

void test_decoding_survives_the_skew_a_real_receiver_adds() {
    // A decoder that compares for equality decodes nothing that was ever
    // actually transmitted.
    const int skews[][2] = {{0, 100}, {0, -100}, {8, 60}, {-8, -60}, {15, 0}};

    for (const auto& s : skews) {
        PulseTrain t;
        TEST_ASSERT_TRUE(encode(Protocol::Nec, 0x04, 0x08, t));
        const PulseTrain dirty = skewTrain(t, s[0], s[1]);

        Decoded d;
        TEST_ASSERT_TRUE(decode(dirty, d));
        TEST_ASSERT_EQUAL_UINT16(0x04, d.address);
        TEST_ASSERT_EQUAL_UINT16(0x08, d.command);
    }
}

void test_rc5_toggle_survives_the_round_trip() {
    // The toggle separates a new press from a held key. Losing it in the
    // decoder means a replayed frame the target ignores as a repeat.
    for (bool toggle : {false, true}) {
        PulseTrain t;
        TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x05, 0x35, t, toggle));
        Decoded d;
        TEST_ASSERT_TRUE(decode(t, d));
        TEST_ASSERT_EQUAL(toggle, d.toggle);
        TEST_ASSERT_EQUAL_UINT16(0x35, d.command);
        TEST_ASSERT_EQUAL_UINT16(0x05, d.address);
    }
}

void test_a_nec_repeat_frame_is_reported_not_rejected() {
    // Header, half-length space, stop mark. It means the key is still down, and
    // calling it a failure makes a held button look like a broken capture.
    PulseTrain t;
    t.count = 3;
    t.us[0] = 9000;
    t.us[1] = 2250;
    t.us[2] = 560;

    Decoded d;
    TEST_ASSERT_TRUE(decode(t, d));
    TEST_ASSERT_TRUE(d.repeat);
}

void test_a_corrupt_nec_command_is_refused_not_stored() {
    // The command byte carries its own complement. Storing a button whose check
    // failed gives the operator a key that will never work.
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Nec, 0x04, 0x08, t));
    t.us[3 + 16 * 2] = 1690;   // flip one bit of the command

    Decoded d;
    TEST_ASSERT_FALSE(decode(t, d));
}

void test_noise_decodes_as_nothing() {
    // Guessing at the closest fit replays as a different button, or as nothing.
    PulseTrain t;
    t.count = 20;
    for (uint8_t i = 0; i < t.count; i++)
        t.us[i] = static_cast<uint16_t>(300 + i * 37);

    Decoded d;
    TEST_ASSERT_FALSE(decode(t, d));

    PulseTrain empty;
    TEST_ASSERT_FALSE(decode(empty, d));
}

void test_an_extended_address_of_complements_is_indistinguishable() {
    // A real protocol ambiguity, not a decoder weakness. Extended NEC differs
    // from plain NEC only in that the second address byte is not the
    // complement of the first -- so an extended address whose halves HAPPEN to
    // be complements produces a frame that is byte-for-byte a plain NEC frame.
    //
    // 0x8877: 0x77 ^ 0x88 == 0xFF. No receiver in the world can tell these
    // apart, so reporting the plain reading is correct rather than a guess, and
    // it replays identically either way.
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::NecExtended, 0x8877, 0x12, t));

    Decoded d;
    TEST_ASSERT_TRUE(decode(t, d));
    TEST_ASSERT_EQUAL(static_cast<int>(Protocol::Nec), static_cast<int>(d.protocol));
    TEST_ASSERT_EQUAL_UINT16(0x77, d.address);
    TEST_ASSERT_EQUAL_UINT16(0x12, d.command);

    // And the proof that it really is the same frame: encoding the plain
    // reading gives identical timings.
    PulseTrain plain;
    TEST_ASSERT_TRUE(encode(Protocol::Nec, 0x77, 0x12, plain));
    TEST_ASSERT_EQUAL_UINT8(t.count, plain.count);
    for (uint8_t i = 0; i < t.count; i++)
        TEST_ASSERT_EQUAL_UINT16(plain.us[i], t.us[i]);
}

void test_nec_extended_is_told_apart_from_plain_nec() {
    // They differ only in whether the address byte is followed by its
    // complement. Mislabelling one replays with the wrong address.
    PulseTrain plain, ext;
    TEST_ASSERT_TRUE(encode(Protocol::Nec, 0x04, 0x08, plain));
    TEST_ASSERT_TRUE(encode(Protocol::NecExtended, 0x1234, 0x08, ext));

    Decoded a, b;
    TEST_ASSERT_TRUE(decode(plain, a));
    TEST_ASSERT_TRUE(decode(ext, b));
    TEST_ASSERT_EQUAL(static_cast<int>(Protocol::Nec), static_cast<int>(a.protocol));
    TEST_ASSERT_EQUAL(static_cast<int>(Protocol::NecExtended),
                      static_cast<int>(b.protocol));
    TEST_ASSERT_EQUAL_UINT16(0x1234, b.address);
}

// ---- the three bugs an adversarial audit found ------------------------------

void test_a_sony15_frame_is_not_decoded_as_a_truncated_sony12() {
    // THE bug worth a test. The width used to be chosen from a RANGE
    // (count >= 25 meant twelve bits), so a real 15-bit frame decoded as a
    // 12-bit one with its top three address bits silently dropped -- a
    // SUCCESSFUL decode of the wrong address, which is the one outcome this
    // decoder is supposed to make impossible.
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Sony15, 0x60, 0x15, t));

    Decoded d;
    TEST_ASSERT_TRUE(decode(t, d));
    TEST_ASSERT_EQUAL(static_cast<int>(Protocol::Sony15), static_cast<int>(d.protocol));
    TEST_ASSERT_EQUAL_UINT16(0x60, d.address);
    TEST_ASSERT_EQUAL_UINT16(0x15, d.command);
}

void test_sony_widths_are_matched_exactly_not_by_range() {
    // A count between the defined widths belongs to no SIRC frame. Rounding it
    // down to the nearest width is how the bug above happened.
    PulseTrain t;
    TEST_ASSERT_TRUE(encode(Protocol::Sony20, 0x1A2B, 0x7F, t));
    TEST_ASSERT_EQUAL_UINT8(42, t.count);

    // Chop three intervals off: no longer any legal width.
    t.count = 39;
    Decoded d;
    TEST_ASSERT_FALSE(decode(t, d));
}

void test_sony_still_forgives_only_the_missing_trailing_space() {
    for (int w = 0; w < 3; w++) {
        const Protocol p = w == 0 ? Protocol::Sony12
                         : w == 1 ? Protocol::Sony15
                                  : Protocol::Sony20;
        PulseTrain t;
        TEST_ASSERT_TRUE(encode(p, 1, 0x15, t));
        t.count--;              // the receiver stopped at the last mark
        Decoded d;
        TEST_ASSERT_TRUE(decode(t, d));
        TEST_ASSERT_EQUAL(static_cast<int>(p), static_cast<int>(d.protocol));
        TEST_ASSERT_EQUAL_UINT16(0x15, d.command);
    }
}

void test_every_rc5_command_survives_a_dropped_trailing_space() {
    // An RC5 frame whose final half-bit is a space ends on silence, which a
    // receiver never records. Requiring all 28 half-bits made exactly half of
    // the 64 commands undecodable -- every one with a zero in the last bit.
    int decoded = 0;
    for (uint16_t cmd = 0; cmd < 64; cmd++) {
        PulseTrain t;
        TEST_ASSERT_TRUE(encode(Protocol::Rc5, 0x05, cmd, t));

        // Simulate the receiver stopping at the last mark.
        PulseTrain clipped = t;
        clipped.count--;

        Decoded d;
        if (decode(clipped, d) && d.command == cmd && d.address == 0x05) decoded++;
    }
    TEST_ASSERT_EQUAL_INT(64, decoded);
}

void test_an_rc5x_frame_is_refused_rather_than_aliased() {
    // In RC5X the SECOND start bit carries the inverted seventh command bit, so
    // a frame with it clear is a command in 64..127. Reading it as plain RC5
    // reports a command exactly 64 too low -- which replays as a DIFFERENT
    // button. The encoder cannot emit RC5X, so refusing is the honest answer
    // and the raw capture stays replayable byte-for-byte.
    //
    // Built by hand: start1=1, start2=0, toggle=0, address=5, command=0.
    const uint16_t bits = static_cast<uint16_t>((1u << 13) | (0u << 12) |
                                                (0u << 11) | (5u << 6) | 0u);
    PulseTrain t;
    bool level[28];
    int n = 0;
    for (int i = 13; i >= 0; i--) {
        const bool one = (bits >> i) & 1;
        level[n++] = !one;
        level[n++] = one;
    }
    int start = 0;
    while (start < n && !level[start]) start++;
    int i = start;
    while (i < n) {
        int run = 1;
        while (i + run < n && level[i + run] == level[i]) run++;
        t.us[t.count++] = static_cast<uint16_t>(889 * run);
        i += run;
    }

    Decoded d;
    TEST_ASSERT_FALSE(decode(t, d));
}

void test_sony15_round_trips_at_its_boundaries() {
    const uint16_t addrs[] = {0x00, 0x01, 0x7F, 0xFF};
    for (uint16_t a : addrs) {
        PulseTrain t;
        TEST_ASSERT_TRUE(encode(Protocol::Sony15, a, 0x7F, t));
        Decoded d;
        TEST_ASSERT_TRUE(decode(t, d));
        TEST_ASSERT_EQUAL_UINT16(a, d.address);
        TEST_ASSERT_EQUAL_UINT16(0x7F, d.command);
    }
    // And an address that does not fit is refused, not truncated.
    PulseTrain t;
    TEST_ASSERT_FALSE(encode(Protocol::Sony15, 0x100, 0x00, t));
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_nec_frame_shape_and_header);
    RUN_TEST(test_nec_round_trips_through_a_decoder);
    RUN_TEST(test_nec_inverse_bytes_are_genuine_complements);
    RUN_TEST(test_nec_extended_drops_the_address_check);

    RUN_TEST(test_sony12_round_trips);
    RUN_TEST(test_sony20_round_trips);
    RUN_TEST(test_sony_uses_a_40khz_carrier);

    RUN_TEST(test_rc5_is_manchester_and_uniform);
    RUN_TEST(test_rc5_round_trips_through_a_decoder);
    RUN_TEST(test_rc5_contains_double_length_intervals);
    RUN_TEST(test_rc5_toggle_bit_actually_changes_the_frame);
    RUN_TEST(test_toggle_is_ignored_by_every_other_protocol);
    RUN_TEST(test_toggled_rc5_is_still_valid_manchester);

    RUN_TEST(test_out_of_range_is_refused_not_truncated);
    RUN_TEST(test_boundary_values_are_accepted);
    RUN_TEST(test_no_train_ever_exceeds_the_buffer);

    RUN_TEST(test_frame_duration_is_plausible);
    RUN_TEST(test_repeat_gaps_present_for_every_protocol);

    RUN_TEST(test_every_protocol_survives_encode_then_decode);
    RUN_TEST(test_decoding_survives_the_skew_a_real_receiver_adds);
    RUN_TEST(test_rc5_toggle_survives_the_round_trip);
    RUN_TEST(test_a_nec_repeat_frame_is_reported_not_rejected);
    RUN_TEST(test_a_corrupt_nec_command_is_refused_not_stored);
    RUN_TEST(test_noise_decodes_as_nothing);
    RUN_TEST(test_an_extended_address_of_complements_is_indistinguishable);
    RUN_TEST(test_nec_extended_is_told_apart_from_plain_nec);

    RUN_TEST(test_a_sony15_frame_is_not_decoded_as_a_truncated_sony12);
    RUN_TEST(test_sony_widths_are_matched_exactly_not_by_range);
    RUN_TEST(test_sony_still_forgives_only_the_missing_trailing_space);
    RUN_TEST(test_every_rc5_command_survives_a_dropped_trailing_space);
    RUN_TEST(test_an_rc5x_frame_is_refused_rather_than_aliased);
    RUN_TEST(test_sony15_round_trips_at_its_boundaries);

    return UNITY_END();
}
