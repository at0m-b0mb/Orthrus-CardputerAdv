// Host tests for the LoRaWAN PHYPayload parser.
//
// The hostile-input cases matter more than the happy ones. FOptsLen is four
// attacker-controlled bits that index into the frame; if it is trusted, a
// crafted uplink reads past the end of the receive buffer. That is the bug
// these tests exist to prevent.

#include <unity.h>

#include <cstring>
#include <vector>

#include "lorawan/phy.h"

using namespace orthrus::lorawan;

namespace {

// EUIs and DevAddr go out little-endian. Test vectors are written the way a
// network server displays them, then reversed here, so a byte-order regression
// shows up as a readable diff rather than a wall of hex.
void pushReversed(std::vector<uint8_t>& v, const uint8_t* be, size_t n) {
    for (size_t i = 0; i < n; i++) v.push_back(be[n - 1 - i]);
}

void pushU16LE(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>(x >> 8));
}

void pushU32LE(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
}

const uint8_t kJoinEuiBE[8] = {0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x01, 0x23, 0x45};
const uint8_t kDevEuiBE[8]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

std::vector<uint8_t> makeJoinRequest(uint16_t devNonce) {
    std::vector<uint8_t> f;
    f.push_back(0x00);  // MHDR: MType=JoinRequest, Major=0
    pushReversed(f, kJoinEuiBE, 8);
    pushReversed(f, kDevEuiBE, 8);
    pushU16LE(f, devNonce);
    pushU32LE(f, 0xDEADBEEF);  // MIC
    return f;
}

// Builds an uplink. `rawFOptsLen` is written into FCtrl verbatim so tests can
// lie about it independently of how many FOpts bytes are actually appended.
std::vector<uint8_t> makeDataUp(uint32_t devAddr, uint16_t fCnt, bool adr,
                                const std::vector<uint8_t>& fOpts, int fPort,
                                const std::vector<uint8_t>& frm,
                                int rawFOptsLen = -1) {
    std::vector<uint8_t> f;
    f.push_back(0x40);  // MType=UnconfirmedDataUp, Major=0
    pushU32LE(f, devAddr);

    const uint8_t optsLen = static_cast<uint8_t>(
        rawFOptsLen >= 0 ? rawFOptsLen : static_cast<int>(fOpts.size()));
    uint8_t fctrl = static_cast<uint8_t>(optsLen & 0x0F);
    if (adr) fctrl |= 0x80;
    f.push_back(fctrl);

    pushU16LE(f, fCnt);
    f.insert(f.end(), fOpts.begin(), fOpts.end());

    if (fPort >= 0) {
        f.push_back(static_cast<uint8_t>(fPort));
        f.insert(f.end(), frm.begin(), frm.end());
    }
    pushU32LE(f, 0x11223344);  // MIC
    return f;
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- join request -----------------------------------------------------------

void test_join_request_decodes_euis_big_endian() {
    const auto f = makeJoinRequest(0x1234);
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL(static_cast<int>(MType::JoinRequest), static_cast<int>(out.mtype));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kJoinEuiBE, out.join.joinEui, 8);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kDevEuiBE, out.join.devEui, 8);
    TEST_ASSERT_EQUAL_UINT16(0x1234, out.join.devNonce);
    TEST_ASSERT_EQUAL_UINT32(0xDEADBEEF, out.mic);
    TEST_ASSERT_TRUE(out.isUplink());
    TEST_ASSERT_TRUE(out.isJoin());
}

void test_join_request_wrong_length_rejected() {
    auto f = makeJoinRequest(0x0001);
    f.pop_back();  // one byte short of a legal join request
    Frame out;
    TEST_ASSERT_FALSE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL(static_cast<int>(ParseError::JoinLengthWrong),
                      static_cast<int>(out.error));
}

// ---- data uplink ------------------------------------------------------------

void test_data_up_basic_fields() {
    const auto f = makeDataUp(0x26011BDA, 5, /*adr=*/true, {}, /*fPort=*/1,
                              {0xAA, 0xBB, 0xCC});
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_TRUE(out.isData());
    TEST_ASSERT_TRUE(out.isUplink());
    TEST_ASSERT_FALSE(out.isConfirmed());
    TEST_ASSERT_EQUAL_UINT32(0x26011BDA, out.data.devAddr);
    TEST_ASSERT_EQUAL_UINT16(5, out.data.fCnt);
    TEST_ASSERT_TRUE(out.data.adr);
    TEST_ASSERT_TRUE(out.data.hasFPort);
    TEST_ASSERT_EQUAL_UINT8(1, out.data.fPort);
    TEST_ASSERT_EQUAL_UINT8(3, out.data.frmPayloadLen);
    TEST_ASSERT_EQUAL_UINT8(0xAA, out.data.frmPayload[0]);
    TEST_ASSERT_EQUAL_UINT8(0xCC, out.data.frmPayload[2]);
}

void test_data_up_with_fopts() {
    const std::vector<uint8_t> opts = {0x03, 0x07, 0x00};  // LinkADRAns-ish
    const auto f = makeDataUp(0x01020304, 9, false, opts, 2, {0x01});
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL_UINT8(3, out.data.fOptsCount);
    TEST_ASSERT_EQUAL_UINT8(0x03, out.data.fOpts[0]);
    TEST_ASSERT_EQUAL_UINT8(2, out.data.fPort);
    TEST_ASSERT_EQUAL_UINT8(1, out.data.frmPayloadLen);
}

void test_data_up_without_fport() {
    // FHDR only: legal, and means "no application payload this time".
    const auto f = makeDataUp(0xAABBCCDD, 77, false, {}, /*fPort=*/-1, {});
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_FALSE(out.data.hasFPort);
    TEST_ASSERT_EQUAL_UINT8(0, out.data.frmPayloadLen);
    TEST_ASSERT_EQUAL_UINT16(77, out.data.fCnt);
}

void test_data_up_fport_zero_is_parsed_not_rejected() {
    // FPort 0 carries MAC commands in the FRMPayload. It is legal, and it is
    // also a finding when combined with FOpts -- but that judgement belongs to
    // the grader, not the parser. The parser's job is to report it faithfully.
    const auto f = makeDataUp(0x12345678, 1, false, {}, /*fPort=*/0, {0x02, 0x03});
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_TRUE(out.data.hasFPort);
    TEST_ASSERT_EQUAL_UINT8(0, out.data.fPort);
    TEST_ASSERT_EQUAL_UINT8(2, out.data.frmPayloadLen);
}

void test_confirmed_uplink_flagged() {
    auto f = makeDataUp(0x00000001, 1, false, {}, 1, {0x00});
    f[0] = 0x80;  // MType = ConfirmedDataUp
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_TRUE(out.isConfirmed());
    TEST_ASSERT_TRUE(out.isUplink());
}

void test_downlink_fpending_decoded_not_classb() {
    // Bit 4 of FCtrl means FPending downlink, ClassB uplink. Same bit, opposite
    // meaning -- a decoder that ignores direction reports nonsense.
    std::vector<uint8_t> f;
    f.push_back(0x60);  // UnconfirmedDataDown
    pushU32LE(f, 0x0A0B0C0D);
    f.push_back(0x10);  // FPending set
    pushU16LE(f, 3);
    pushU32LE(f, 0);
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_FALSE(out.isUplink());
    TEST_ASSERT_TRUE(out.data.fPending);
    TEST_ASSERT_FALSE(out.data.classB);
}

// ---- hostile input ----------------------------------------------------------

void test_fopts_len_lying_is_rejected() {
    // FCtrl claims 15 bytes of FOpts; the frame carries none. A parser that
    // trusts this reads 15 bytes past the MACPayload.
    const auto f = makeDataUp(0xDEADBEEF, 1, false, {}, /*fPort=*/-1, {},
                              /*rawFOptsLen=*/15);
    Frame out;
    TEST_ASSERT_FALSE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL(static_cast<int>(ParseError::FOptsOverrun),
                      static_cast<int>(out.error));
}

void test_fopts_len_exactly_filling_frame_is_accepted() {
    // The boundary the overrun check must not over-reject.
    const std::vector<uint8_t> opts(15, 0x55);
    const auto f = makeDataUp(0x01010101, 1, false, opts, /*fPort=*/-1, {});
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL_UINT8(15, out.data.fOptsCount);
    TEST_ASSERT_FALSE(out.data.hasFPort);
}

void test_truncated_frames_never_parse() {
    // Every prefix of a valid frame must either parse or fail cleanly -- never
    // read out of bounds. Run under ASan this is the test that catches it.
    const auto full = makeDataUp(0x26011BDA, 5, true, {0x01, 0x02}, 1, {0xAA});
    for (size_t n = 0; n < full.size(); n++) {
        Frame out;
        parse(full.data(), n, out);  // must not crash
    }
    TEST_ASSERT_TRUE(true);
}

void test_too_short_rejected() {
    const uint8_t buf[4] = {0x40, 0x00, 0x00, 0x00};
    Frame out;
    TEST_ASSERT_FALSE(parse(buf, sizeof(buf), out));
    TEST_ASSERT_EQUAL(static_cast<int>(ParseError::TooShort),
                      static_cast<int>(out.error));
}

void test_null_buffer_rejected() {
    Frame out;
    TEST_ASSERT_FALSE(parse(nullptr, 32, out));
    TEST_ASSERT_EQUAL(static_cast<int>(ParseError::TooShort),
                      static_cast<int>(out.error));
}

void test_bad_major_rejected() {
    auto f = makeDataUp(0x11111111, 1, false, {}, 1, {0x00});
    f[0] |= 0x01;  // Major = 1, undefined in LoRaWAN R1
    Frame out;
    TEST_ASSERT_FALSE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL(static_cast<int>(ParseError::BadMajor),
                      static_cast<int>(out.error));
}

void test_macpayload_too_short_for_fhdr() {
    // MHDR + 6 bytes + MIC: one byte short of a complete FHDR.
    std::vector<uint8_t> f;
    f.push_back(0x40);
    for (int i = 0; i < 6; i++) f.push_back(0x00);
    pushU32LE(f, 0);
    Frame out;
    TEST_ASSERT_FALSE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL(static_cast<int>(ParseError::MacPayloadTooShort),
                      static_cast<int>(out.error));
}

// ---- join accept ------------------------------------------------------------

void test_join_accept_lengths() {
    TEST_ASSERT_TRUE(joinAcceptLengthIsPlausible(17));   // without CFList
    TEST_ASSERT_TRUE(joinAcceptLengthIsPlausible(33));   // with CFList
    TEST_ASSERT_FALSE(joinAcceptLengthIsPlausible(20));
    TEST_ASSERT_FALSE(joinAcceptLengthIsPlausible(0));
}

void test_join_accept_parses_but_stays_opaque() {
    std::vector<uint8_t> f(17, 0x00);
    f[0] = 0x20;  // MType = JoinAccept
    Frame out;
    TEST_ASSERT_TRUE(parse(f.data(), f.size(), out));
    TEST_ASSERT_EQUAL(static_cast<int>(MType::JoinAccept), static_cast<int>(out.mtype));
    TEST_ASSERT_TRUE(out.isJoin());
    TEST_ASSERT_FALSE(out.isUplink());
}

// ---- naming -----------------------------------------------------------------

void test_names_are_present_for_every_enum() {
    for (int i = 0; i < 8; i++) {
        const char* n = mtypeName(static_cast<MType>(i));
        TEST_ASSERT_NOT_NULL(n);
        TEST_ASSERT_TRUE(std::strlen(n) > 0);
    }
    for (int i = 0; i <= static_cast<int>(ParseError::JoinLengthWrong); i++) {
        const char* n = errorName(static_cast<ParseError>(i));
        TEST_ASSERT_NOT_NULL(n);
        TEST_ASSERT_TRUE(std::strlen(n) > 0);
    }
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_join_request_decodes_euis_big_endian);
    RUN_TEST(test_join_request_wrong_length_rejected);

    RUN_TEST(test_data_up_basic_fields);
    RUN_TEST(test_data_up_with_fopts);
    RUN_TEST(test_data_up_without_fport);
    RUN_TEST(test_data_up_fport_zero_is_parsed_not_rejected);
    RUN_TEST(test_confirmed_uplink_flagged);
    RUN_TEST(test_downlink_fpending_decoded_not_classb);

    RUN_TEST(test_fopts_len_lying_is_rejected);
    RUN_TEST(test_fopts_len_exactly_filling_frame_is_accepted);
    RUN_TEST(test_truncated_frames_never_parse);
    RUN_TEST(test_too_short_rejected);
    RUN_TEST(test_null_buffer_rejected);
    RUN_TEST(test_bad_major_rejected);
    RUN_TEST(test_macpayload_too_short_for_fhdr);

    RUN_TEST(test_join_accept_lengths);
    RUN_TEST(test_join_accept_parses_but_stays_opaque);

    RUN_TEST(test_names_are_present_for_every_enum);

    return UNITY_END();
}
