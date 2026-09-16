// Host tests for credential identification and grading.
//
// The identification tests use real ATQA/SAK pairs as cards actually transmit
// them. The grading tests are mostly about the ceiling: a badge read cannot
// tell you what the reader checks, so A+ has to be unreachable, and a card
// relying on Crypto1 cannot be described as sound however tidy it is otherwise.

#include <unity.h>

#include <cstring>

#include "credential/grade.h"
#include "credential/tag.h"

using namespace orthrus::credential;

namespace {

TagIdentity tag(uint16_t atqa, uint8_t sak, uint8_t uidLen,
                const uint8_t* uid = nullptr) {
    TagIdentity t;
    t.atqa   = atqa;
    t.sak    = sak;
    t.uidLen = uidLen;
    if (uid) std::memcpy(t.uid, uid, uidLen);
    else for (uint8_t i = 0; i < uidLen; i++) t.uid[i] = static_cast<uint8_t>(0x10 + i);
    return t;
}

// Real cards, as they answer anticollision.
TagIdentity classic1k()   { return tag(0x0004, 0x08, 4); }
TagIdentity classic4k()   { return tag(0x0002, 0x18, 4); }
TagIdentity classicMini() { return tag(0x0004, 0x09, 4); }
TagIdentity ultralight()  { return tag(0x0044, 0x00, 7); }
TagIdentity desfireEv1()  { return tag(0x0344, 0x20, 7); }
TagIdentity smartMx()     { return tag(0x0004, 0x28, 7); }  // ISO-DEP + Crypto1

}  // namespace

void setUp() {}
void tearDown() {}

// ---- identification ---------------------------------------------------------

void test_mifare_classic_variants_identified() {
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareClassic1K),
                      static_cast<int>(classic1k().family()));
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareClassic4K),
                      static_cast<int>(classic4k().family()));
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareClassicMini),
                      static_cast<int>(classicMini().family()));
}

void test_ultralight_identified() {
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareUltralight),
                      static_cast<int>(ultralight().family()));
}

void test_desfire_identified_from_iso_dep() {
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareDesfire),
                      static_cast<int>(desfireEv1().family()));
    TEST_ASSERT_TRUE(desfireEv1().isIso14443_4());
    TEST_ASSERT_FALSE(desfireEv1().isClassicCompatible());
}

void test_card_that_is_both_iso_dep_and_crypto1_reports_the_weaker_half() {
    // SAK 0x28 sets both bits. A lookup table keyed on SAK alone gets this
    // wrong and calls it a strong card, when the Crypto1 sectors it is also
    // carrying are the thing an attacker will actually go for.
    const TagIdentity t = smartMx();
    TEST_ASSERT_TRUE(t.isIso14443_4());
    TEST_ASSERT_TRUE(t.isClassicCompatible());
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifarePlusSL1),
                      static_cast<int>(t.family()));
    TEST_ASSERT_EQUAL(static_cast<int>(Cipher::Crypto1),
                      static_cast<int>(cipherFor(t.family())));
}

void test_desfire_identified_from_ats_marker() {
    // The real ATS a DESFire EV1 answers with. ATQA here is deliberately NOT
    // the DESFire value, so this can only pass via the ATS path.
    TagIdentity t = tag(0x0004, 0x20, 7);
    const uint8_t ats[] = {0x06, 0x75, 0x77, 0x81, 0x02, 0x80};
    std::memcpy(t.ats, ats, sizeof(ats));
    t.atsLen = sizeof(ats);
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareDesfire),
                      static_cast<int>(t.family()));
}

void test_desfire_marker_found_at_the_very_end_of_the_ats() {
    // The off-by-one that the first version of this code had: a loop bound one
    // pair short silently misses a signature sitting at the end of the buffer.
    TagIdentity t = tag(0x0004, 0x20, 7);
    const uint8_t ats[] = {0x06, 0x75, 0x77, 0x81, 0x02};
    std::memcpy(t.ats, ats, sizeof(ats));
    t.atsLen = sizeof(ats);
    TEST_ASSERT_EQUAL(static_cast<int>(Family::MifareDesfire),
                      static_cast<int>(t.family()));
}

void test_iso_dep_without_a_known_ats_is_not_guessed() {
    // An ISO-DEP card we cannot identify must be reported as exactly that,
    // rather than optimistically called a DESFire.
    TagIdentity t = tag(0x0004, 0x20, 7);
    const uint8_t ats[] = {0x05, 0x78, 0x80, 0x70, 0x02};
    std::memcpy(t.ats, ats, sizeof(ats));
    t.atsLen = sizeof(ats);
    TEST_ASSERT_EQUAL(static_cast<int>(Family::JavaCardOrSmartMX),
                      static_cast<int>(t.family()));
    TEST_ASSERT_EQUAL(static_cast<int>(Cipher::Unknown),
                      static_cast<int>(cipherFor(t.family())));
}

void test_uid_kinds() {
    TEST_ASSERT_EQUAL(static_cast<int>(UidKind::Single4Byte),
                      static_cast<int>(classic1k().uidKind()));
    TEST_ASSERT_EQUAL(static_cast<int>(UidKind::Double7Byte),
                      static_cast<int>(ultralight().uidKind()));

    const uint8_t ten[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    TEST_ASSERT_EQUAL(static_cast<int>(UidKind::Triple10Byte),
                      static_cast<int>(tag(0x0004, 0x20, 10, ten).uidKind()));
}

void test_random_uid_is_not_treated_as_a_weak_identifier() {
    // A 4-byte UID beginning 0x08 is declared random-per-session by the spec.
    // That is a privacy feature; grading it as a cloneable identifier would
    // punish the card for doing the right thing.
    const uint8_t rnd[4] = {0x08, 0xAB, 0xCD, 0xEF};
    const TagIdentity t = tag(0x0344, 0x20, 4, rnd);
    TEST_ASSERT_EQUAL(static_cast<int>(UidKind::RandomPerSession),
                      static_cast<int>(t.uidKind()));
    TEST_ASSERT_FALSE(assess(t).findings.has(FindingId::ClonableUid));
}

void test_cipher_mapping() {
    TEST_ASSERT_EQUAL(static_cast<int>(Cipher::Crypto1),
                      static_cast<int>(cipherFor(Family::MifareClassic1K)));
    TEST_ASSERT_EQUAL(static_cast<int>(Cipher::None),
                      static_cast<int>(cipherFor(Family::MifareUltralight)));
    TEST_ASSERT_EQUAL(static_cast<int>(Cipher::Aes),
                      static_cast<int>(cipherFor(Family::MifareDesfire)));
    TEST_ASSERT_EQUAL(static_cast<int>(Cipher::Des3),
                      static_cast<int>(cipherFor(Family::MifareUltralightC)));
}

// ---- the ceiling ------------------------------------------------------------

void test_no_card_can_earn_a_plus_from_a_read() {
    // The rule the whole file is built around. Even the best card on the
    // market, read perfectly, cannot be graded A+ -- because the reader's
    // policy is the real control and it is invisible from here.
    const auto a = assess(desfireEv1());
    TEST_ASSERT_NOT_EQUAL(static_cast<int>(Grade::APlus), static_cast<int>(a.grade));
    TEST_ASSERT_TRUE(a.score <= kReadAloneCeiling);
    TEST_ASSERT_TRUE(a.findings.has(FindingId::ReaderPolicyUnknown));
}

void test_best_case_card_still_grades_well() {
    // The ceiling must not make the grader uniformly punitive, or an operator
    // learns to ignore it. A DESFire should still clearly outrank a Classic.
    const auto good = assess(desfireEv1());
    const auto bad  = assess(classic1k());
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::A), static_cast<int>(good.grade));
    TEST_ASSERT_TRUE(good.score > bad.score);
}

void test_crypto1_cannot_be_graded_sound() {
    const auto a = assess(classic1k());
    TEST_ASSERT_TRUE(a.findings.has(FindingId::BrokenCipher));
    TEST_ASSERT_TRUE(a.score <= kBrokenCipherCeiling);
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::F), static_cast<int>(a.grade));
}

void test_no_cryptography_grades_worse_than_broken_cryptography() {
    // Nothing at all is worse than something broken: an Ultralight needs no
    // attack, just a blank and thirty seconds.
    const auto none   = assess(ultralight());
    const auto broken = assess(classic1k());
    TEST_ASSERT_TRUE(none.score < broken.score);
    TEST_ASSERT_TRUE(none.findings.has(FindingId::NoCryptography));
}

void test_default_key_is_the_worst_thing_we_can_find() {
    TagIdentity t = classic1k();
    t.triedDefaultKeys   = true;
    t.defaultKeyAccepted = true;

    const auto a = assess(t);
    TEST_ASSERT_TRUE(a.findings.has(FindingId::DefaultKeyAccepted));
    const Finding* f = a.findings.get(FindingId::DefaultKeyAccepted);
    TEST_ASSERT_EQUAL(static_cast<int>(Severity::Critical), static_cast<int>(f->sev));
    TEST_ASSERT_TRUE(a.score <= kDefaultKeyCeiling);
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::F), static_cast<int>(a.grade));
}

void test_trying_keys_and_failing_is_not_a_finding() {
    // Absence of evidence again: probing and finding nothing must not be
    // recorded as if we had found something.
    TagIdentity t = classic1k();
    t.triedDefaultKeys   = true;
    t.defaultKeyAccepted = false;

    const auto a = assess(t);
    TEST_ASSERT_FALSE(a.findings.has(FindingId::DefaultKeyAccepted));
    TEST_ASSERT_FALSE(a.surfaceOnly);
}

void test_ceiling_is_a_curve_not_a_clip() {
    // Two Crypto1 cards, one additionally handing over a default key. Both are
    // capped, but the worse one must still rank worse.
    TagIdentity plain = classic1k();
    TagIdentity worse = classic1k();
    worse.triedDefaultKeys   = true;
    worse.defaultKeyAccepted = true;

    TEST_ASSERT_TRUE(assess(plain).score > assess(worse).score);
}

void test_card_carrying_classic_sectors_is_penalised() {
    const auto a = assess(smartMx());
    TEST_ASSERT_TRUE(a.findings.has(FindingId::ClassicSectorsPresent));
    TEST_ASSERT_TRUE(a.score <= kBrokenCipherCeiling);
}

void test_four_byte_uid_flagged() {
    TEST_ASSERT_TRUE(assess(classic1k()).findings.has(FindingId::ClonableUid));
    TEST_ASSERT_FALSE(assess(ultralight()).findings.has(FindingId::ClonableUid));
}

// ---- honesty about what was not done ----------------------------------------

void test_unprobed_card_is_marked_surface_only() {
    const auto a = assess(desfireEv1());
    TEST_ASSERT_TRUE(a.surfaceOnly);
    TEST_ASSERT_TRUE(a.findings.has(FindingId::DeeperProbeNotRun));
}

void test_probed_card_is_not_marked_surface_only() {
    TagIdentity t = desfireEv1();
    t.triedReadWithoutAuth = true;
    TEST_ASSERT_FALSE(assess(t).surfaceOnly);
}

void test_info_findings_cost_nothing() {
    // ReaderPolicyUnknown and DeeperProbeNotRun are statements about us, not
    // accusations about the card, so they must not move the score.
    TagIdentity t = desfireEv1();
    t.triedReadWithoutAuth = true;   // clears DeeperProbeNotRun
    t.readableWithoutAuth  = false;

    const auto probed = assess(t);
    const auto raw    = assess(desfireEv1());
    TEST_ASSERT_EQUAL_UINT8(raw.score, probed.score);
}

void test_readable_without_auth_not_double_counted_on_open_cards() {
    // An Ultralight being readable is not a separate failing, it is what
    // NoCryptography already says. Counting both would punish it twice.
    TagIdentity t = ultralight();
    t.triedReadWithoutAuth = true;
    t.readableWithoutAuth  = true;
    TEST_ASSERT_FALSE(assess(t).findings.has(FindingId::ReadableWithoutAuth));
}

void test_readable_without_auth_counts_on_a_card_that_should_have_stopped_us() {
    TagIdentity t = desfireEv1();
    t.triedReadWithoutAuth = true;
    t.readableWithoutAuth  = true;

    const auto a = assess(t);
    TEST_ASSERT_TRUE(a.findings.has(FindingId::ReadableWithoutAuth));
    TEST_ASSERT_TRUE(a.score < assess(desfireEv1()).score);
}

void test_confidence_never_reaches_certainty() {
    TagIdentity t = classic1k();
    t.triedDefaultKeys   = true;
    t.defaultKeyAccepted = true;
    const auto a = assess(t);
    for (uint8_t i = 0; i < a.findings.count; i++) {
        if (findingCarriesConfidence(a.findings.items[i].sev))
            TEST_ASSERT_TRUE(a.findings.items[i].confidence <= kConfidenceCeiling);
    }
}

void test_finding_set_bounds_and_text() {
    FindingSet fs;
    for (int i = 0; i < FindingSet::kMax + 4; i++)
        fs.add(FindingId::ClonableUid, Severity::Low, 50);
    TEST_ASSERT_EQUAL_UINT8(FindingSet::kMax, fs.count);
    TEST_ASSERT_FALSE(fs.add(FindingId::ClonableUid, Severity::Low, 0));

    for (int i = 0; i <= static_cast<int>(FindingId::DeeperProbeNotRun); i++) {
        const auto id = static_cast<FindingId>(i);
        TEST_ASSERT_TRUE(std::strlen(findingTitle(id)) > 0);
        TEST_ASSERT_TRUE(std::strlen(findingDetail(id)) > 0);
    }
    for (int i = 0; i <= static_cast<int>(Family::Iso15693); i++)
        TEST_ASSERT_TRUE(std::strlen(familyName(static_cast<Family>(i))) > 0);
    for (int i = 0; i <= static_cast<int>(Grade::F); i++)
        TEST_ASSERT_TRUE(std::strlen(gradeName(static_cast<Grade>(i))) > 0);
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_mifare_classic_variants_identified);
    RUN_TEST(test_ultralight_identified);
    RUN_TEST(test_desfire_identified_from_iso_dep);
    RUN_TEST(test_card_that_is_both_iso_dep_and_crypto1_reports_the_weaker_half);
    RUN_TEST(test_desfire_identified_from_ats_marker);
    RUN_TEST(test_desfire_marker_found_at_the_very_end_of_the_ats);
    RUN_TEST(test_iso_dep_without_a_known_ats_is_not_guessed);
    RUN_TEST(test_uid_kinds);
    RUN_TEST(test_random_uid_is_not_treated_as_a_weak_identifier);
    RUN_TEST(test_cipher_mapping);

    RUN_TEST(test_no_card_can_earn_a_plus_from_a_read);
    RUN_TEST(test_best_case_card_still_grades_well);
    RUN_TEST(test_crypto1_cannot_be_graded_sound);
    RUN_TEST(test_no_cryptography_grades_worse_than_broken_cryptography);
    RUN_TEST(test_default_key_is_the_worst_thing_we_can_find);
    RUN_TEST(test_trying_keys_and_failing_is_not_a_finding);
    RUN_TEST(test_ceiling_is_a_curve_not_a_clip);
    RUN_TEST(test_card_carrying_classic_sectors_is_penalised);
    RUN_TEST(test_four_byte_uid_flagged);

    RUN_TEST(test_unprobed_card_is_marked_surface_only);
    RUN_TEST(test_probed_card_is_not_marked_surface_only);
    RUN_TEST(test_info_findings_cost_nothing);
    RUN_TEST(test_readable_without_auth_not_double_counted_on_open_cards);
    RUN_TEST(test_readable_without_auth_counts_on_a_card_that_should_have_stopped_us);
    RUN_TEST(test_confidence_never_reaches_certainty);
    RUN_TEST(test_finding_set_bounds_and_text);

    return UNITY_END();
}
