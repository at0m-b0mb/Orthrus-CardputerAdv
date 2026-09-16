// Host tests for payload inspection, the device census, and the grader.
//
// The tests that matter most here are the ones that prove the tool REFUSES to
// draw a conclusion: short payloads it will not call plaintext, rollovers it
// will not call resets, and absence findings it will not emit when it could not
// hear the band.

#include <unity.h>

#include <cstring>
#include <vector>

#include "lorawan/census.h"
#include "lorawan/findings.h"
#include "lorawan/payload.h"
#include "lorawan/phy.h"

using namespace orthrus::lorawan;

namespace {

RxMeta meta(uint32_t t, uint8_t sf = 7, int16_t rssi = -100) {
    RxMeta m;
    m.freqHz  = 868100000;
    m.sf      = sf;
    m.bwKhz   = 125;
    m.rssiDbm = rssi;
    m.snrDb   = 7;
    m.timeMs  = t;
    return m;
}

Frame dataUp(uint32_t devAddr, uint16_t fCnt, bool adr = true,
             bool confirmed = false) {
    Frame f;
    f.mtype = confirmed ? MType::ConfirmedDataUp : MType::UnconfirmedDataUp;
    f.major = 0;
    f.data.devAddr = devAddr;
    f.data.fCnt    = fCnt;
    f.data.adr     = adr;
    f.data.hasFPort = true;
    f.data.fPort    = 1;
    return f;
}

Frame joinReq(const uint8_t devEui[8], uint16_t nonce) {
    Frame f;
    f.mtype = MType::JoinRequest;
    f.major = 0;
    std::memcpy(f.join.devEui, devEui, 8);
    f.join.devNonce = nonce;
    return f;
}

// Coverage a single SX1262 actually achieves: one channel, one SF, out of
// EU868's 8 x 6. That is 2%.
CaptureContext oneRadioContext(uint32_t listenedMs = 60000) {
    CaptureContext c;
    c.listenedMs       = listenedMs;
    c.channelsCovered  = 1;
    c.channelsInRegion = 8;
    c.sfCovered        = 1;
    c.sfInRegion       = 6;
    return c;
}

CaptureContext fullCoverageContext(uint32_t listenedMs = 60000) {
    CaptureContext c;
    c.listenedMs       = listenedMs;
    c.channelsCovered  = 8;
    c.channelsInRegion = 8;
    c.sfCovered        = 6;
    c.sfInRegion       = 6;
    return c;
}

const uint8_t kEuiA[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
const uint8_t kEuiB[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

}  // namespace

void setUp() {}
void tearDown() {}

// ---- payload inspection -----------------------------------------------------

void test_short_payload_never_called_plaintext() {
    // "OK" is printable but two bytes of ciphertext are printable ~14% of the
    // time. Claiming plaintext here would be a lie dressed as a finding.
    const uint8_t p[] = {'O', 'K'};
    const auto v = inspectPayload(p, sizeof(p));
    TEST_ASSERT_FALSE(v.looksPlaintext());
    TEST_ASSERT_EQUAL_UINT8(0, v.confidence);
}

void test_seven_bytes_still_refused() {
    const uint8_t p[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
    TEST_ASSERT_EQUAL_UINT8(7, kMinPlaintextLen - 1);
    const auto v = inspectPayload(p, sizeof(p));
    TEST_ASSERT_FALSE(v.looksPlaintext());
}

void test_json_payload_detected_with_high_confidence() {
    const char* s = "{\"t\":21.5,\"h\":48}";
    const auto v = inspectPayload(reinterpret_cast<const uint8_t*>(s),
                                  static_cast<uint8_t>(std::strlen(s)));
    TEST_ASSERT_TRUE(v.looksPlaintext());
    TEST_ASSERT_EQUAL(static_cast<int>(PayloadSignal::StructuredText),
                      static_cast<int>(v.signal));
    TEST_ASSERT_EQUAL_UINT8(97, v.confidence);
}

void test_long_printable_scores_higher_than_short() {
    const char* shortish = "abcdefgh";          // 8
    const char* longer   = "abcdefghijklmnop";  // 16
    const auto a = inspectPayload(reinterpret_cast<const uint8_t*>(shortish), 8);
    const auto b = inspectPayload(reinterpret_cast<const uint8_t*>(longer), 16);
    TEST_ASSERT_TRUE(a.looksPlaintext());
    TEST_ASSERT_TRUE(b.looksPlaintext());
    TEST_ASSERT_TRUE(b.confidence > a.confidence);
}

void test_ciphertext_like_payload_not_flagged() {
    // High-entropy, non-printable bytes: what correct AES output looks like.
    const uint8_t p[] = {0x8F, 0x02, 0xD1, 0x77, 0xB4, 0x19, 0xEE, 0x5A,
                         0x03, 0xC7, 0x91, 0x2B, 0xF0, 0x66, 0xAD, 0x38};
    const auto v = inspectPayload(p, sizeof(p));
    TEST_ASSERT_FALSE(v.looksPlaintext());
}

void test_all_zero_payload_flagged_as_low_diversity() {
    const uint8_t p[20] = {0};
    const auto v = inspectPayload(p, sizeof(p));
    TEST_ASSERT_TRUE(v.looksPlaintext());
    TEST_ASSERT_EQUAL(static_cast<int>(PayloadSignal::LowDiversity),
                      static_cast<int>(v.signal));
}

void test_null_payload_safe() {
    const auto v = inspectPayload(nullptr, 32);
    TEST_ASSERT_FALSE(v.looksPlaintext());
}

void test_confidence_never_reaches_certainty() {
    const char* s = "{\"a\":\"bbbbbbbbbbbbbbbbbbbb\"}";
    const auto v = inspectPayload(reinterpret_cast<const uint8_t*>(s),
                                  static_cast<uint8_t>(std::strlen(s)));
    TEST_ASSERT_TRUE(v.confidence <= 97);
}

// ---- frame counter judgement ------------------------------------------------

void test_rollover_is_not_a_reset() {
    TEST_ASSERT_TRUE(isFCntRollover(0xFFFE, 0x0002));
    TEST_ASSERT_TRUE(isFCntRollover(0xF001, 0x0000));

    Census c;
    c.observe(dataUp(0x1000, 0xFFFE), meta(1000));
    c.observe(dataUp(0x1000, 0x0003), meta(2000));
    TEST_ASSERT_EQUAL_UINT32(1, c.size());
    TEST_ASSERT_EQUAL_UINT32(0, c.at(0).fcntResets);
    TEST_ASSERT_EQUAL_UINT32(1, c.at(0).fcntRollovers);
}

void test_midrange_decrease_is_a_reset_not_a_rollover() {
    // 0x8000 -> 0x0001 is a reboot, not a wrap. Excusing it would hide the
    // single most serious thing this tool can find.
    TEST_ASSERT_FALSE(isFCntRollover(0x8000, 0x0001));

    Census c;
    c.observe(dataUp(0x2000, 0x8000), meta(1000));
    c.observe(dataUp(0x2000, 0x0001), meta(2000));
    TEST_ASSERT_EQUAL_UINT32(1, c.at(0).fcntResets);
    TEST_ASSERT_EQUAL_UINT32(0, c.at(0).fcntRollovers);
}

void test_repeated_counter_counted_separately_from_reset() {
    Census c;
    c.observe(dataUp(0x3000, 10), meta(1000));
    c.observe(dataUp(0x3000, 10), meta(1100));
    c.observe(dataUp(0x3000, 10), meta(1200));
    TEST_ASSERT_EQUAL_UINT32(2, c.at(0).fcntRepeats);
    TEST_ASSERT_EQUAL_UINT32(0, c.at(0).fcntResets);
}

void test_forward_jump_recorded() {
    Census c;
    c.observe(dataUp(0x4000, 1), meta(1000));
    c.observe(dataUp(0x4000, 50), meta(2000));
    TEST_ASSERT_EQUAL_UINT16(49, c.at(0).maxFCntJump);
    TEST_ASSERT_EQUAL_UINT32(0, c.at(0).fcntResets);
}

// ---- census bookkeeping -----------------------------------------------------

void test_sessions_and_joiners_tracked_separately() {
    Census c;
    c.observe(dataUp(0xAAAA, 1), meta(1000));
    c.observe(joinReq(kEuiA, 0x1111), meta(1100));
    c.observe(joinReq(kEuiB, 0x2222), meta(1200));
    TEST_ASSERT_EQUAL_UINT32(3, c.size());
    TEST_ASSERT_EQUAL_UINT32(2, c.joinsObserved());
}

void test_devnonce_reuse_detected() {
    Census c;
    c.observe(joinReq(kEuiA, 0x1234), meta(1000));
    c.observe(joinReq(kEuiA, 0x5678), meta(2000));
    c.observe(joinReq(kEuiA, 0x1234), meta(3000));  // reused
    TEST_ASSERT_EQUAL_UINT32(1, c.size());
    TEST_ASSERT_EQUAL_UINT32(3, c.at(0).joinCount);
    TEST_ASSERT_EQUAL_UINT32(1, c.at(0).devNonceRepeats);
}

void test_nonce_ring_does_not_false_positive_on_distinct_nonces() {
    Census c;
    for (uint16_t i = 0; i < 20; i++) c.observe(joinReq(kEuiA, i), meta(1000 + i));
    TEST_ASSERT_EQUAL_UINT32(0, c.at(0).devNonceRepeats);
}

void test_table_full_is_reported_not_silently_dropped() {
    Census c;
    for (uint32_t i = 0; i < Census::kMaxDevices + 10; i++)
        c.observe(dataUp(0x10000 + i, 1), meta(1000 + i));
    TEST_ASSERT_EQUAL_UINT32(Census::kMaxDevices, c.size());
    TEST_ASSERT_EQUAL_UINT32(10, c.framesDropped());
}

void test_invalid_frame_ignored() {
    Census c;
    Frame bad;
    bad.error = ParseError::FOptsOverrun;
    TEST_ASSERT_EQUAL_INT(-1, c.observe(bad, meta(1000)));
    TEST_ASSERT_EQUAL_UINT32(0, c.size());
}

void test_radio_extremes_tracked() {
    Census c;
    c.observe(dataUp(0x5000, 1), meta(1000, 12, -120));
    c.observe(dataUp(0x5000, 2), meta(2000, 7, -80));
    TEST_ASSERT_EQUAL_INT16(-80, c.at(0).bestRssiDbm);
    TEST_ASSERT_EQUAL_UINT8(7, c.at(0).sfMin);
    TEST_ASSERT_EQUAL_UINT8(12, c.at(0).sfMax);
}

// ---- coverage arithmetic ----------------------------------------------------

void test_single_radio_coverage_is_two_percent() {
    TEST_ASSERT_EQUAL_UINT8(2, oneRadioContext().coveragePercent());
    TEST_ASSERT_EQUAL_UINT8(100, fullCoverageContext().coveragePercent());
}

// ---- grading: presence is proof ---------------------------------------------

void test_fcnt_reset_scores_at_full_weight_even_at_low_coverage() {
    // We SAW it. Missing 98% of the band does not make what we saw less true.
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen  = 10;
    d.fcntResets  = 1;
    d.adrSetCount = 10;

    const auto a = assess(d, oneRadioContext());
    TEST_ASSERT_TRUE(a.findings.has(FindingId::FCntReset));
    const Finding* f = a.findings.get(FindingId::FCntReset);
    TEST_ASSERT_EQUAL_UINT8(95, f->confidence);
    TEST_ASSERT_EQUAL(static_cast<int>(Severity::Critical), static_cast<int>(f->sev));
}

void test_plaintext_finding_caps_grade_at_d_or_worse() {
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen = 20;
    d.adrSetCount = 20;
    d.plaintextCount = 5;
    d.bestPlaintextConfidence = 97;

    const auto a = assess(d, fullCoverageContext());
    TEST_ASSERT_TRUE(a.findings.has(FindingId::PlaintextPayload));
    TEST_ASSERT_TRUE(a.score <= 45);
    TEST_ASSERT_TRUE(a.grade == Grade::D || a.grade == Grade::F);
}

void test_ceiling_is_a_curve_not_a_clip() {
    // Two leaking devices, one otherwise clean and one also resetting its
    // counter. Both are capped, but the worse one must still rank worse --
    // a clip would flatten them to the same score.
    DeviceRecord tidy;
    tidy.kind = DeviceKind::Session;
    tidy.framesSeen = 20;
    tidy.adrSetCount = 20;
    tidy.plaintextCount = 1;
    tidy.bestPlaintextConfidence = 80;

    DeviceRecord messy = tidy;
    messy.fcntResets  = 3;
    messy.fcntRepeats = 6;

    const auto a = assess(tidy, fullCoverageContext());
    const auto b = assess(messy, fullCoverageContext());
    TEST_ASSERT_TRUE(a.score > b.score);
}

// ---- grading: absence is not proof ------------------------------------------

void test_absence_finding_suppressed_when_coverage_too_low() {
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen  = 30;
    d.adrSetCount = 30;

    const auto a = assess(d, oneRadioContext());
    // 2% coverage: we must NOT accuse this device of being ABP.
    TEST_ASSERT_FALSE(a.findings.has(FindingId::AbpSuspected));
    TEST_ASSERT_TRUE(a.findings.has(FindingId::CoverageTooLow));
}

void test_absence_finding_appears_but_stays_capped_at_full_coverage() {
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen  = 30;
    d.adrSetCount = 30;

    const auto a = assess(d, fullCoverageContext(20u * 60u * 1000u));
    TEST_ASSERT_TRUE(a.findings.has(FindingId::AbpSuspected));
    const Finding* f = a.findings.get(FindingId::AbpSuspected);
    TEST_ASSERT_TRUE(f->confidence <= kAbsenceCeiling);
}

void test_coverage_note_does_not_cost_score() {
    // An Info finding is a statement about us, not about the device.
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen  = 30;
    d.adrSetCount = 30;

    const auto a = assess(d, oneRadioContext());
    TEST_ASSERT_TRUE(a.findings.has(FindingId::CoverageTooLow));
    TEST_ASSERT_EQUAL_UINT8(100, a.score);
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::APlus), static_cast<int>(a.grade));
}

void test_thin_evidence_cannot_earn_top_grade() {
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen  = 2;   // too few to judge counter behaviour
    d.adrSetCount = 2;

    const auto a = assess(d, fullCoverageContext());
    TEST_ASSERT_TRUE(a.score <= 84);
    TEST_ASSERT_TRUE(a.grade != Grade::APlus && a.grade != Grade::A);
}

void test_adr_disabled_needs_enough_frames() {
    DeviceRecord few;
    few.kind = DeviceKind::Session;
    few.framesSeen = 2;
    few.adrClearCount = 2;
    TEST_ASSERT_FALSE(assess(few, fullCoverageContext()).findings.has(
        FindingId::AdrDisabled));

    DeviceRecord many;
    many.kind = DeviceKind::Session;
    many.framesSeen = 20;
    many.adrClearCount = 20;
    TEST_ASSERT_TRUE(assess(many, fullCoverageContext()).findings.has(
        FindingId::AdrDisabled));
}

void test_devnonce_reuse_graded_high() {
    DeviceRecord d;
    d.kind = DeviceKind::Joiner;
    d.framesSeen = 6;
    d.joinCount = 6;
    d.devNonceRepeats = 2;

    const auto a = assess(d, fullCoverageContext());
    const Finding* f = a.findings.get(FindingId::DevNonceReuse);
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL(static_cast<int>(Severity::High), static_cast<int>(f->sev));
}

void test_clean_device_can_still_reach_top_grade() {
    // The grader must not be uniformly punitive, or an operator learns to
    // ignore it. A well-behaved device with real evidence behind it earns A+.
    DeviceRecord d;
    d.kind = DeviceKind::Session;
    d.framesSeen  = 50;
    d.adrSetCount = 50;
    d.sfMin = 7;
    d.sfMax = 9;

    const auto a = assess(d, oneRadioContext());
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::APlus), static_cast<int>(a.grade));
}

void test_every_finding_has_text() {
    for (int i = 0; i <= static_cast<int>(FindingId::CoverageTooLow); i++) {
        const auto id = static_cast<FindingId>(i);
        TEST_ASSERT_TRUE(std::strlen(findingTitle(id)) > 0);
        TEST_ASSERT_TRUE(std::strlen(findingDetail(id)) > 0);
    }
    for (int i = 0; i <= static_cast<int>(Severity::Critical); i++)
        TEST_ASSERT_TRUE(std::strlen(severityName(static_cast<Severity>(i))) > 0);
    for (int i = 0; i <= static_cast<int>(Grade::F); i++)
        TEST_ASSERT_TRUE(std::strlen(gradeName(static_cast<Grade>(i))) > 0);
}

void test_finding_set_respects_its_bound() {
    FindingSet fs;
    for (int i = 0; i < FindingSet::kMax + 5; i++)
        fs.add(FindingId::FCntRepeat, Severity::Low, 50);
    TEST_ASSERT_EQUAL_UINT8(FindingSet::kMax, fs.count);
}

void test_zero_confidence_finding_is_not_recorded() {
    FindingSet fs;
    TEST_ASSERT_FALSE(fs.add(FindingId::AbpSuspected, Severity::Low, 0));
    TEST_ASSERT_EQUAL_UINT8(0, fs.count);
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_short_payload_never_called_plaintext);
    RUN_TEST(test_seven_bytes_still_refused);
    RUN_TEST(test_json_payload_detected_with_high_confidence);
    RUN_TEST(test_long_printable_scores_higher_than_short);
    RUN_TEST(test_ciphertext_like_payload_not_flagged);
    RUN_TEST(test_all_zero_payload_flagged_as_low_diversity);
    RUN_TEST(test_null_payload_safe);
    RUN_TEST(test_confidence_never_reaches_certainty);

    RUN_TEST(test_rollover_is_not_a_reset);
    RUN_TEST(test_midrange_decrease_is_a_reset_not_a_rollover);
    RUN_TEST(test_repeated_counter_counted_separately_from_reset);
    RUN_TEST(test_forward_jump_recorded);

    RUN_TEST(test_sessions_and_joiners_tracked_separately);
    RUN_TEST(test_devnonce_reuse_detected);
    RUN_TEST(test_nonce_ring_does_not_false_positive_on_distinct_nonces);
    RUN_TEST(test_table_full_is_reported_not_silently_dropped);
    RUN_TEST(test_invalid_frame_ignored);
    RUN_TEST(test_radio_extremes_tracked);

    RUN_TEST(test_single_radio_coverage_is_two_percent);

    RUN_TEST(test_fcnt_reset_scores_at_full_weight_even_at_low_coverage);
    RUN_TEST(test_plaintext_finding_caps_grade_at_d_or_worse);
    RUN_TEST(test_ceiling_is_a_curve_not_a_clip);

    RUN_TEST(test_absence_finding_suppressed_when_coverage_too_low);
    RUN_TEST(test_absence_finding_appears_but_stays_capped_at_full_coverage);
    RUN_TEST(test_coverage_note_does_not_cost_score);
    RUN_TEST(test_thin_evidence_cannot_earn_top_grade);
    RUN_TEST(test_adr_disabled_needs_enough_frames);
    RUN_TEST(test_devnonce_reuse_graded_high);
    RUN_TEST(test_clean_device_can_still_reach_top_grade);

    RUN_TEST(test_every_finding_has_text);
    RUN_TEST(test_finding_set_respects_its_bound);
    RUN_TEST(test_zero_confidence_finding_is_not_recorded);

    return UNITY_END();
}
