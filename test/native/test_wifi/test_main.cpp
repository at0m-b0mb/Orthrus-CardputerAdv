// Host tests for Wi-Fi network grading.

#include <unity.h>

#include <cstdio>
#include <cstring>
#include <initializer_list>

#include "wifi/network.h"

using namespace orthrus::wifi;

namespace {

Network net(Security sec, const char* ssid = "office", uint8_t ch = 6,
            int16_t rssi = -55) {
    Network n;
    std::snprintf(n.ssid, kSsidLen, "%s", ssid);
    for (uint8_t i = 0; i < kBssidLen; i++) n.bssid[i] = static_cast<uint8_t>(i + 1);
    n.channel  = ch;
    n.rssi     = rssi;
    n.security = sec;
    return n;
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- the ceiling ------------------------------------------------------------

void test_no_network_earns_a_plus_from_a_scan() {
    // A scan sees the beacon, not the passphrase, client isolation, or whether
    // the AP is who it claims. None of those can be waived.
    for (auto sec : {Security::Wpa3Sae, Security::Wpa2Enterprise}) {
        const auto a = assess(net(sec));
        TEST_ASSERT_NOT_EQUAL(static_cast<int>(Grade::APlus),
                              static_cast<int>(a.grade));
        TEST_ASSERT_TRUE(a.findings.has(FindingId::KeyStrengthUnknown));
        TEST_ASSERT_TRUE(a.score <= kScanOnlyCeiling);
    }
}

void test_strong_networks_still_grade_well() {
    // The ceiling must not flatten everything, or the grade stops informing.
    const auto wpa3 = assess(net(Security::Wpa3Sae));
    const auto open = assess(net(Security::Open));
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::A), static_cast<int>(wpa3.grade));
    TEST_ASSERT_TRUE(wpa3.score > open.score);
}

void test_open_network_is_the_worst_case() {
    const auto a = assess(net(Security::Open));
    TEST_ASSERT_TRUE(a.findings.has(FindingId::OpenNetwork));
    TEST_ASSERT_TRUE(a.score <= kOpenCeiling);
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::F), static_cast<int>(a.grade));
}

void test_wep_grades_as_broken() {
    const auto a = assess(net(Security::Wep));
    TEST_ASSERT_TRUE(a.findings.has(FindingId::WepEncryption));
    TEST_ASSERT_TRUE(a.score <= kBrokenCeiling);
    TEST_ASSERT_EQUAL(static_cast<int>(Grade::F), static_cast<int>(a.grade));
}

void test_open_grades_worse_than_wep() {
    // Nothing at all is worse than something broken: WEP at least needs a
    // capture and a few minutes.
    TEST_ASSERT_TRUE(assess(net(Security::Open)).score <
                     assess(net(Security::Wep)).score);
}

void test_mixed_mode_penalised_for_the_weaker_half() {
    // WPA/WPA2 mixed leaves the old half reachable, so it must not grade as
    // WPA2 does.
    const auto mixed = assess(net(Security::WpaWpa2Psk));
    const auto wpa2  = assess(net(Security::Wpa2Psk));
    TEST_ASSERT_TRUE(mixed.findings.has(FindingId::WpaTkipReachable));
    TEST_ASSERT_TRUE(mixed.score < wpa2.score);
}

void test_wpa3_transition_mode_flagged_but_not_condemned() {
    const auto trans = assess(net(Security::Wpa2Wpa3Mixed));
    const auto pure  = assess(net(Security::Wpa3Sae));
    TEST_ASSERT_TRUE(trans.findings.has(FindingId::Wpa2TransitionMode));
    TEST_ASSERT_TRUE(trans.score < pure.score);
    TEST_ASSERT_TRUE(trans.grade == Grade::B || trans.grade == Grade::A);
}

void test_enterprise_has_no_shared_key_finding() {
    const auto a = assess(net(Security::Wpa2Enterprise));
    TEST_ASSERT_FALSE(a.findings.has(FindingId::PreSharedKeyOnly));
}

// ---- hedged findings --------------------------------------------------------

void test_duplicate_ssid_is_hedged_not_accused() {
    // Enterprise roaming and an evil twin look identical from outside. Calling
    // every multi-AP site an attack would train the operator to ignore it.
    const auto one  = assess(net(Security::Wpa2Psk), 1);
    const auto many = assess(net(Security::Wpa2Psk), 4);

    TEST_ASSERT_TRUE(one.findings.has(FindingId::DuplicateSsid));
    const Finding* f1 = one.findings.get(FindingId::DuplicateSsid);
    const Finding* f4 = many.findings.get(FindingId::DuplicateSsid);
    TEST_ASSERT_EQUAL(static_cast<int>(Severity::Medium), static_cast<int>(f1->sev));
    TEST_ASSERT_TRUE(f1->confidence < 70);     // never confident
    TEST_ASSERT_TRUE(f4->confidence > f1->confidence);  // but more so with more
}

void test_no_duplicates_no_finding() {
    TEST_ASSERT_FALSE(assess(net(Security::Wpa2Psk), 0)
                          .findings.has(FindingId::DuplicateSsid));
}

void test_hidden_network_detected_and_only_a_low() {
    Network n = net(Security::Wpa2Psk, "");
    TEST_ASSERT_TRUE(n.hidden());
    const auto a = assess(n);
    TEST_ASSERT_TRUE(a.findings.has(FindingId::HiddenNetwork));
    const Finding* f = a.findings.get(FindingId::HiddenNetwork);
    TEST_ASSERT_EQUAL(static_cast<int>(Severity::Low), static_cast<int>(f->sev));
}

void test_named_network_is_not_hidden() {
    TEST_ASSERT_FALSE(net(Security::Wpa2Psk, "office").hidden());
}

// ---- helpers ----------------------------------------------------------------

void test_band_detection() {
    TEST_ASSERT_TRUE(net(Security::Open, "x", 1).is24GHz());
    TEST_ASSERT_TRUE(net(Security::Open, "x", 14).is24GHz());
    TEST_ASSERT_FALSE(net(Security::Open, "x", 36).is24GHz());
    TEST_ASSERT_FALSE(net(Security::Open, "x", 0).is24GHz());
}

void test_bssid_formatting() {
    const uint8_t b[6] = {0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03};
    char out[18];
    formatBssid(b, out);
    TEST_ASSERT_EQUAL_STRING("AA:BB:CC:01:02:03", out);
}

void test_broken_and_open_classification() {
    TEST_ASSERT_TRUE(isOpen(Security::Open));
    TEST_ASSERT_FALSE(isOpen(Security::Wep));
    TEST_ASSERT_TRUE(isBroken(Security::Wep));
    TEST_ASSERT_TRUE(isBroken(Security::WpaPsk));
    TEST_ASSERT_FALSE(isBroken(Security::Wpa2Psk));
}

void test_every_name_and_detail_present() {
    for (int i = 0; i <= static_cast<int>(FindingId::KeyStrengthUnknown); i++) {
        const auto id = static_cast<FindingId>(i);
        TEST_ASSERT_TRUE(std::strlen(findingTitle(id)) > 0);
        TEST_ASSERT_TRUE(std::strlen(findingDetail(id)) > 0);
    }
    for (int i = 0; i <= static_cast<int>(Security::Unknown); i++)
        TEST_ASSERT_TRUE(std::strlen(securityName(static_cast<Security>(i))) > 0);
    for (int i = 0; i <= static_cast<int>(Grade::F); i++)
        TEST_ASSERT_TRUE(std::strlen(gradeName(static_cast<Grade>(i))) > 0);
}

void test_score_never_exceeds_one_hundred() {
    for (int i = 0; i <= static_cast<int>(Security::Unknown); i++)
        for (uint8_t dup = 0; dup < 6; dup++)
            TEST_ASSERT_TRUE(
                assess(net(static_cast<Security>(i)), dup).score <= 100);
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_no_network_earns_a_plus_from_a_scan);
    RUN_TEST(test_strong_networks_still_grade_well);
    RUN_TEST(test_open_network_is_the_worst_case);
    RUN_TEST(test_wep_grades_as_broken);
    RUN_TEST(test_open_grades_worse_than_wep);
    RUN_TEST(test_mixed_mode_penalised_for_the_weaker_half);
    RUN_TEST(test_wpa3_transition_mode_flagged_but_not_condemned);
    RUN_TEST(test_enterprise_has_no_shared_key_finding);

    RUN_TEST(test_duplicate_ssid_is_hedged_not_accused);
    RUN_TEST(test_no_duplicates_no_finding);
    RUN_TEST(test_hidden_network_detected_and_only_a_low);
    RUN_TEST(test_named_network_is_not_hidden);

    RUN_TEST(test_band_detection);
    RUN_TEST(test_bssid_formatting);
    RUN_TEST(test_broken_and_open_classification);
    RUN_TEST(test_every_name_and_detail_present);
    RUN_TEST(test_score_never_exceeds_one_hundred);

    return UNITY_END();
}
