// Host tests for the 802.11 frames this device builds by hand.
//
// Two kinds of assertion, and both are needed.
//
// BYTE-EXACT, against the standard's layout. A frame builder is either right or
// silently useless: a wrong offset does not throw, it produces a frame every
// stack on the air quietly discards while the screen counts up and concludes
// "no effect seen" -- which reads identically to a properly protected network.
//
// ROUND-TRIPPED, through this firmware's own parser. If the builder and the
// parser were to drift apart, both could still be internally consistent and the
// device would be emitting frames it cannot itself recognise. Parsing every
// built frame back closes that loop.

#include <unity.h>

#include <cstring>

#include "dot11/inject.h"

using namespace orthrus::dot11;

namespace {

const uint8_t kAp[6]        = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t kSta[6]       = {0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

uint16_t le16At(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

// The sequence number out of a built frame's sequence control field.
uint16_t seqOf(const uint8_t* f) { return static_cast<uint16_t>(le16At(f + 22) >> 4); }

// Finds an information element in a beacon or probe-response body. Returns the
// pointer to its length byte's payload, and sets `len`.
const uint8_t* findIe(const uint8_t* frame, size_t total, uint8_t id, uint8_t* len) {
    const size_t bodyAt = 24 + 12;   // header, then timestamp/interval/capability
    size_t i = bodyAt;
    while (i + 2 <= total) {
        const uint8_t eid  = frame[i];
        const uint8_t elen = frame[i + 1];
        if (i + 2 + elen > total) return nullptr;
        if (eid == id) {
            *len = elen;
            return frame + i + 2;
        }
        i += 2 + elen;
    }
    return nullptr;
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- disconnects ------------------------------------------------------------

void test_a_deauth_is_twenty_six_bytes_laid_out_as_the_standard_says() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildDeauth(f, sizeof(f), kBroadcast, kAp, kAp,
                                 kReasonClass3NonAssoc, s);
    TEST_ASSERT_EQUAL_size_t(26, n);

    TEST_ASSERT_EQUAL_UINT8(0xC0, f[0]);   // management, subtype 12
    TEST_ASSERT_EQUAL_UINT8(0x00, f[1]);   // no flags set
    TEST_ASSERT_EQUAL_UINT8(0x00, f[2]);   // duration, left to the MAC
    TEST_ASSERT_EQUAL_UINT8(0x00, f[3]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kBroadcast, f + 4, 6);   // addr1 receiver
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, f + 10, 6);         // addr2 transmitter
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, f + 16, 6);         // addr3 BSSID
    TEST_ASSERT_EQUAL_UINT16(7, le16At(f + 24));           // reason, little endian
}

void test_a_disassoc_differs_from_a_deauth_only_in_its_subtype() {
    uint8_t a[kInjectMax], b[kInjectMax];
    Sequencer s1, s2;
    const size_t na = buildDeauth(a, sizeof(a), kSta, kAp, kAp, 7, s1);
    const size_t nb = buildDisassoc(b, sizeof(b), kSta, kAp, kAp, 7, s2);

    TEST_ASSERT_EQUAL_size_t(na, nb);
    TEST_ASSERT_EQUAL_UINT8(0xC0, a[0]);
    TEST_ASSERT_EQUAL_UINT8(0xA0, b[0]);   // subtype 10
    // Everything after the first byte is identical.
    TEST_ASSERT_EQUAL_MEMORY(a + 1, b + 1, na - 1);
}

void test_the_source_is_separate_from_the_bssid_so_both_directions_can_be_sent() {
    // A disconnect is only honoured in the direction it plausibly travels.
    // Spoofing the access point at a client is one test; spoofing the client at
    // the access point is a different one, and equipment differs in which it
    // obeys. Sending both is what actually clears a cell.
    uint8_t f[kInjectMax];
    Sequencer s;

    buildDeauth(f, sizeof(f), kSta, kAp, kAp, 7, s);     // AP -> station
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, f + 4, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  f + 10, 6);

    buildDeauth(f, sizeof(f), kAp, kSta, kAp, 7, s);     // station -> AP
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  f + 4, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, f + 10, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  f + 16, 6);      // still the BSSID
}

void test_every_reason_code_reaches_the_frame_intact() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const uint16_t codes[] = {kReasonUnspecified, kReasonInactivity,
                              kReasonClass3NonAssoc, 15, 255};
    for (uint16_t c : codes) {
        buildDeauth(f, sizeof(f), kSta, kAp, kAp, c, s);
        TEST_ASSERT_EQUAL_UINT16(c, le16At(f + 24));
    }
}

// ---- sequence numbers -------------------------------------------------------

void test_sequence_numbers_advance_rather_than_repeating_forever() {
    // en_sys_seq=false means the MAC does not fill this in, so a builder that
    // leaves it at zero sends every frame with the same sequence number --
    // and a receiving stack may treat the second as a retransmission of the
    // first and drop it. A burst of two hundred then lands as one.
    uint8_t f[kInjectMax];
    Sequencer s;
    for (uint16_t expect = 0; expect < 5; expect++) {
        buildDeauth(f, sizeof(f), kSta, kAp, kAp, 7, s);
        TEST_ASSERT_EQUAL_UINT16(expect, seqOf(f));
    }
}

void test_the_sequence_number_wraps_at_twelve_bits() {
    Sequencer s;
    for (int i = 0; i < 4095; i++) (void)s.next();
    TEST_ASSERT_EQUAL_UINT16(4095, s.peek());
    (void)s.next();
    TEST_ASSERT_EQUAL_UINT16(0, s.peek());
}

void test_the_fragment_number_is_always_zero() {
    uint8_t f[kInjectMax];
    Sequencer s;
    for (int i = 0; i < 20; i++) {
        buildDeauth(f, sizeof(f), kSta, kAp, kAp, 7, s);
        TEST_ASSERT_EQUAL_UINT8(0, f[22] & 0x0F);
    }
}

void test_one_sequencer_is_shared_across_frame_shapes() {
    uint8_t f[kInjectMax];
    Sequencer s;
    buildDeauth(f, sizeof(f), kSta, kAp, kAp, 7, s);
    TEST_ASSERT_EQUAL_UINT16(0, seqOf(f));
    buildBeacon(f, sizeof(f), "ORTHRUS-1", kAp, 6, BeaconSecurity::Open, s);
    TEST_ASSERT_EQUAL_UINT16(1, seqOf(f));
    buildDisassoc(f, sizeof(f), kSta, kAp, kAp, 7, s);
    TEST_ASSERT_EQUAL_UINT16(2, seqOf(f));
}

// ---- beacons ----------------------------------------------------------------

void test_a_beacon_carries_its_name_channel_and_rates() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-lab", kAp, 6,
                                 BeaconSecurity::Open, s);
    TEST_ASSERT_TRUE(n > 24 + 12);

    TEST_ASSERT_EQUAL_UINT8(0x80, f[0]);   // subtype 8, beacon
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kBroadcast, f + 4, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, f + 10, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, f + 16, 6);

    // Timestamp is zero: it is the access point's own microsecond clock and
    // nothing receiving the frame can check it against anything.
    for (int i = 0; i < 8; i++) TEST_ASSERT_EQUAL_UINT8(0, f[24 + i]);
    TEST_ASSERT_EQUAL_UINT16(100, le16At(f + 32));   // beacon interval, TU

    uint8_t len = 0;
    const uint8_t* ssid = findIe(f, n, 0x00, &len);
    TEST_ASSERT_NOT_NULL(ssid);
    TEST_ASSERT_EQUAL_UINT8(11, len);
    TEST_ASSERT_EQUAL_MEMORY("ORTHRUS-lab", ssid, 11);

    const uint8_t* ds = findIe(f, n, 0x03, &len);
    TEST_ASSERT_NOT_NULL(ds);
    TEST_ASSERT_EQUAL_UINT8(1, len);
    TEST_ASSERT_EQUAL_UINT8(6, ds[0]);

    const uint8_t* rates = findIe(f, n, 0x01, &len);
    TEST_ASSERT_NOT_NULL(rates);
    TEST_ASSERT_EQUAL_UINT8(8, len);
    TEST_ASSERT_EQUAL_UINT8(0x82, rates[0]);   // 1 Mbps, basic
}

void test_an_open_beacon_does_not_set_the_privacy_bit_and_carries_no_rsn() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-1", kAp, 1,
                                 BeaconSecurity::Open, s);
    const uint16_t cap = le16At(f + 34);
    TEST_ASSERT_EQUAL_UINT16(0x0001, cap);   // ESS only

    uint8_t len = 0;
    TEST_ASSERT_NULL(findIe(f, n, 0x30, &len));
}

void test_a_wpa2_beacon_sets_privacy_and_advertises_psk_with_ccmp() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-1", kAp, 1,
                                 BeaconSecurity::Wpa2Psk, s);
    TEST_ASSERT_EQUAL_UINT16(0x0011, le16At(f + 34));   // ESS | Privacy

    uint8_t len = 0;
    const uint8_t* rsn = findIe(f, n, 0x30, &len);
    TEST_ASSERT_NOT_NULL(rsn);
    TEST_ASSERT_EQUAL_UINT8(20, len);
    TEST_ASSERT_EQUAL_UINT16(1, le16At(rsn));            // version 1
    // Group cipher CCMP, pairwise CCMP, AKM PSK -- each an 00-0F-AC selector.
    const uint8_t ccmp[4] = {0x00, 0x0F, 0xAC, 0x04};
    const uint8_t psk[4]  = {0x00, 0x0F, 0xAC, 0x02};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ccmp, rsn + 2, 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ccmp, rsn + 8, 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(psk,  rsn + 14, 4);
    TEST_ASSERT_EQUAL_UINT16(0x0000, le16At(rsn + 18));  // no PMF
}

void test_a_wpa3_beacon_advertises_sae_and_requires_protected_management() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-1", kAp, 1,
                                 BeaconSecurity::Wpa3Sae, s);
    uint8_t len = 0;
    const uint8_t* rsn = findIe(f, n, 0x30, &len);
    TEST_ASSERT_NOT_NULL(rsn);
    const uint8_t sae[4] = {0x00, 0x0F, 0xAC, 0x08};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sae, rsn + 14, 4);
    // MFPC (bit 6) and MFPR (bit 7) both set.
    TEST_ASSERT_EQUAL_UINT16(0x00C0, le16At(rsn + 18));
}

void test_an_empty_name_produces_a_hidden_network_beacon() {
    // A real shape, and worth being able to emit: a zero-length SSID element
    // rather than no element at all.
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "", kAp, 1, BeaconSecurity::Open, s);
    TEST_ASSERT_TRUE(n > 0);
    uint8_t len = 0xFF;
    const uint8_t* ssid = findIe(f, n, 0x00, &len);
    TEST_ASSERT_NOT_NULL(ssid);
    TEST_ASSERT_EQUAL_UINT8(0, len);
}

void test_an_overlong_name_is_truncated_rather_than_refused() {
    // The alternative is a surface that silently emits nothing because
    // somebody typed a long name.
    const char* fortyChars = "ORTHRUS-0123456789012345678901234567890";
    TEST_ASSERT_EQUAL_size_t(39, std::strlen(fortyChars));
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), fortyChars, kAp, 1,
                                 BeaconSecurity::Open, s);
    TEST_ASSERT_TRUE(n > 0);
    uint8_t len = 0;
    TEST_ASSERT_NOT_NULL(findIe(f, n, 0x00, &len));
    TEST_ASSERT_EQUAL_UINT8(32, len);
}

// ---- the channel switch -----------------------------------------------------

void test_a_csa_beacon_carries_the_switch_element_with_mode_one() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildCsaBeacon(f, sizeof(f), "ORTHRUS-1", kAp, 6, 11, 2,
                                    BeaconSecurity::Wpa2Psk, s);
    TEST_ASSERT_TRUE(n > 0);

    uint8_t len = 0;
    const uint8_t* csa = findIe(f, n, 0x25, &len);
    TEST_ASSERT_NOT_NULL(csa);
    TEST_ASSERT_EQUAL_UINT8(3, len);
    // Mode 1 tells clients to stop transmitting until the switch happens,
    // which is what makes this disruptive rather than merely rude.
    TEST_ASSERT_EQUAL_UINT8(1, csa[0]);
    TEST_ASSERT_EQUAL_UINT8(11, csa[1]);   // where everybody is being sent
    TEST_ASSERT_EQUAL_UINT8(2, csa[2]);    // beacon intervals remaining
}

void test_a_csa_beacon_still_claims_the_channel_it_is_sitting_on() {
    // The DS parameter set says where the beacon IS; the CSA says where it is
    // going. Confusing the two produces a beacon that claims to already be
    // somewhere it is not, and clients discard it.
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildCsaBeacon(f, sizeof(f), "ORTHRUS-1", kAp, 6, 11, 0,
                                    BeaconSecurity::Open, s);
    uint8_t len = 0;
    const uint8_t* ds = findIe(f, n, 0x03, &len);
    TEST_ASSERT_NOT_NULL(ds);
    TEST_ASSERT_EQUAL_UINT8(6, ds[0]);
}

// ---- probe responses --------------------------------------------------------

void test_a_probe_response_is_addressed_to_the_station_that_asked() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildProbeResponse(f, sizeof(f), "AirportFreeWiFi", kAp,
                                        kSta, 6, BeaconSecurity::Open, s);
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_UINT8(0x50, f[0]);   // subtype 5, probe response
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, f + 4, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  f + 10, 6);

    // The name the station asked for, echoed back. That IS Karma.
    uint8_t len = 0;
    const uint8_t* ssid = findIe(f, n, 0x00, &len);
    TEST_ASSERT_NOT_NULL(ssid);
    TEST_ASSERT_EQUAL_UINT8(15, len);
    TEST_ASSERT_EQUAL_MEMORY("AirportFreeWiFi", ssid, 15);
}

// ---- joining ----------------------------------------------------------------

void test_an_auth_request_is_open_system_transaction_one() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildAuthRequest(f, sizeof(f), kAp, kSta, s);
    TEST_ASSERT_EQUAL_size_t(30, n);
    TEST_ASSERT_EQUAL_UINT8(0xB0, f[0]);   // subtype 11
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  f + 4, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, f + 10, 6);
    TEST_ASSERT_EQUAL_UINT16(0, le16At(f + 24));   // open system
    TEST_ASSERT_EQUAL_UINT16(1, le16At(f + 26));   // transaction 1
    TEST_ASSERT_EQUAL_UINT16(0, le16At(f + 28));   // status successful
}

void test_an_assoc_request_asks_for_psk_so_a_pmkid_can_be_volunteered() {
    // An access point will not volunteer a PMKID in answer to a request whose
    // AKM it does not support, so this element is the difference between a
    // solicitation and a refusal.
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildAssocRequest(f, sizeof(f), "TestNet", kAp, kSta, s);
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_UINT8(0x00, f[0]);   // subtype 0, association request
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  f + 4, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, f + 10, 6);
    TEST_ASSERT_EQUAL_UINT16(0x0011, le16At(f + 24));   // ESS | Privacy
    TEST_ASSERT_EQUAL_UINT16(10, le16At(f + 26));       // listen interval

    // The elements start right after the four fixed bytes, so the generic
    // beacon-body walker is off by eight here. Walk from the right place.
    size_t i = 24 + 4;
    bool sawSsid = false, sawRsn = false;
    while (i + 2 <= n) {
        const uint8_t id = f[i], len = f[i + 1];
        if (id == 0x00) {
            sawSsid = true;
            TEST_ASSERT_EQUAL_UINT8(7, len);
            TEST_ASSERT_EQUAL_MEMORY("TestNet", f + i + 2, 7);
        }
        if (id == 0x30) {
            sawRsn = true;
            const uint8_t psk[4] = {0x00, 0x0F, 0xAC, 0x02};
            TEST_ASSERT_EQUAL_UINT8_ARRAY(psk, f + i + 2 + 14, 4);
        }
        i += 2 + len;
    }
    TEST_ASSERT_TRUE(sawSsid);
    TEST_ASSERT_TRUE(sawRsn);
}

// ---- refusing to write a half-frame ----------------------------------------

void test_a_buffer_too_small_writes_nothing_rather_than_a_partial_frame() {
    uint8_t tiny[8];
    Sequencer s;
    TEST_ASSERT_EQUAL_size_t(0, buildDeauth(tiny, sizeof(tiny), kSta, kAp, kAp, 7, s));
    TEST_ASSERT_EQUAL_size_t(0, buildDisassoc(tiny, sizeof(tiny), kSta, kAp, kAp, 7, s));
    TEST_ASSERT_EQUAL_size_t(0, buildBeacon(tiny, sizeof(tiny), "x", kAp, 1,
                                            BeaconSecurity::Open, s));
    TEST_ASSERT_EQUAL_size_t(0, buildAuthRequest(tiny, sizeof(tiny), kAp, kSta, s));
    TEST_ASSERT_EQUAL_size_t(0, buildAssocRequest(tiny, sizeof(tiny), "x", kAp, kSta, s));
    TEST_ASSERT_EQUAL_size_t(0, buildProbeResponse(tiny, sizeof(tiny), "x", kAp,
                                                   kSta, 1, BeaconSecurity::Open, s));
    TEST_ASSERT_EQUAL_size_t(0, buildCsaBeacon(tiny, sizeof(tiny), "x", kAp, 1, 6,
                                               0, BeaconSecurity::Open, s));
}

void test_a_beacon_that_would_not_fit_writes_nothing() {
    // 24 bytes of header fit; the body does not. The builder must return 0
    // rather than a header with nothing behind it.
    uint8_t buf[30];
    Sequencer s;
    TEST_ASSERT_EQUAL_size_t(0, buildBeacon(buf, sizeof(buf), "ORTHRUS-1", kAp, 1,
                                            BeaconSecurity::Wpa2Psk, s));
}

void test_a_null_argument_is_refused() {
    uint8_t f[kInjectMax];
    Sequencer s;
    TEST_ASSERT_EQUAL_size_t(0, buildDeauth(nullptr, sizeof(f), kSta, kAp, kAp, 7, s));
    TEST_ASSERT_EQUAL_size_t(0, buildDeauth(f, sizeof(f), nullptr, kAp, kAp, 7, s));
    TEST_ASSERT_EQUAL_size_t(0, buildBeacon(f, sizeof(f), "x", nullptr, 1,
                                            BeaconSecurity::Open, s));
    TEST_ASSERT_EQUAL_size_t(0, buildAuthRequest(f, sizeof(f), kAp, nullptr, s));
}

void test_a_null_ssid_is_a_hidden_network_rather_than_a_refusal() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), nullptr, kAp, 1,
                                 BeaconSecurity::Open, s);
    TEST_ASSERT_TRUE(n > 0);
    uint8_t len = 0xFF;
    TEST_ASSERT_NOT_NULL(findIe(f, n, 0x00, &len));
    TEST_ASSERT_EQUAL_UINT8(0, len);
}

void test_every_builder_stays_inside_the_declared_maximum() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const char* longest = "ORTHRUS-01234567890123456789012";   // 32 bytes
    TEST_ASSERT_TRUE(buildCsaBeacon(f, sizeof(f), longest, kAp, 6, 11, 3,
                                    BeaconSecurity::Wpa3Sae, s) <= kInjectMax);
    TEST_ASSERT_TRUE(buildAssocRequest(f, sizeof(f), longest, kAp, kSta, s)
                     <= kInjectMax);
    TEST_ASSERT_TRUE(buildProbeResponse(f, sizeof(f), longest, kAp, kSta, 6,
                                        BeaconSecurity::Wpa3Sae, s) <= kInjectMax);
}

// ---- round-trip through this firmware's own parser -------------------------

void test_a_built_deauth_parses_back_as_a_deauth() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildDeauth(f, sizeof(f), kSta, kAp, kAp, 7, s);

    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    TEST_ASSERT_EQUAL(static_cast<int>(FrameType::Management),
                      static_cast<int>(fi.type));
    TEST_ASSERT_EQUAL_UINT8(kSubtypeDeauth, fi.subtype);
    TEST_ASSERT_EQUAL_UINT16(24, fi.headerLen);
    TEST_ASSERT_FALSE(fi.protectedFrame);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, fi.addr1, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  fi.addr2, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp,  fi.addr3, 6);
}

void test_a_built_beacon_parses_back_with_the_name_and_security_it_was_given() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-twin", kAp, 11,
                                 BeaconSecurity::Wpa2Psk, s);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    TEST_ASSERT_EQUAL_UINT8(kSubtypeBeacon, fi.subtype);

    BeaconInfo bi;
    TEST_ASSERT_TRUE(parseBeacon(f + fi.headerLen, n - fi.headerLen, bi));
    TEST_ASSERT_EQUAL_STRING("ORTHRUS-twin", bi.ssid);
    TEST_ASSERT_TRUE(bi.ssidPresent);
    TEST_ASSERT_FALSE(bi.ssidHidden);
    TEST_ASSERT_EQUAL_UINT8(11, bi.channel);
    TEST_ASSERT_TRUE(bi.hasRsn);
    TEST_ASSERT_FALSE(bi.truncated);
    TEST_ASSERT_TRUE(bi.rsn.akmPsk);
    TEST_ASSERT_TRUE(bi.rsn.cipherCcmp);
    TEST_ASSERT_FALSE(bi.rsn.pmfRequired);
}

void test_a_built_wpa3_beacon_parses_back_as_requiring_protected_management() {
    // This is the pair that matters for Twin beacon: the device can emit a
    // beacon whose own parser agrees it is WPA3-with-PMF, so a twin that
    // DOWNGRADES a network is demonstrably a downgrade.
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-sae", kAp, 6,
                                 BeaconSecurity::Wpa3Sae, s);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    BeaconInfo bi;
    TEST_ASSERT_TRUE(parseBeacon(f + fi.headerLen, n - fi.headerLen, bi));
    TEST_ASSERT_TRUE(bi.rsn.akmSae);
    TEST_ASSERT_FALSE(bi.rsn.akmPsk);
    TEST_ASSERT_TRUE(bi.rsn.pmfCapable);
    TEST_ASSERT_TRUE(bi.rsn.pmfRequired);
}

void test_a_built_open_beacon_parses_back_with_no_rsn_at_all() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-open", kAp, 1,
                                 BeaconSecurity::Open, s);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    BeaconInfo bi;
    TEST_ASSERT_TRUE(parseBeacon(f + fi.headerLen, n - fi.headerLen, bi));
    TEST_ASSERT_FALSE(bi.hasRsn);
    TEST_ASSERT_FALSE(bi.hasWpa);
    TEST_ASSERT_FALSE(bi.rsn.present);
}

void test_a_built_csa_beacon_parses_back_without_being_called_truncated() {
    // The channel-switch element sits between the DS parameter set and the RSN
    // element. If it were written with a wrong length the parser would walk off
    // the end and flag truncation, so this is a real check on the layout.
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildCsaBeacon(f, sizeof(f), "ORTHRUS-csa", kAp, 6, 11, 1,
                                    BeaconSecurity::Wpa2Psk, s);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    BeaconInfo bi;
    TEST_ASSERT_TRUE(parseBeacon(f + fi.headerLen, n - fi.headerLen, bi));
    TEST_ASSERT_FALSE(bi.truncated);
    TEST_ASSERT_EQUAL_STRING("ORTHRUS-csa", bi.ssid);
    TEST_ASSERT_EQUAL_UINT8(6, bi.channel);
    TEST_ASSERT_TRUE(bi.hasRsn);
}

void test_a_built_probe_response_parses_back_as_one() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildProbeResponse(f, sizeof(f), "CorpGuest", kAp, kSta, 3,
                                        BeaconSecurity::Open, s);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    TEST_ASSERT_EQUAL_UINT8(kSubtypeProbeResp, fi.subtype);
    BeaconInfo bi;
    TEST_ASSERT_TRUE(parseBeacon(f + fi.headerLen, n - fi.headerLen, bi));
    TEST_ASSERT_EQUAL_STRING("CorpGuest", bi.ssid);
    TEST_ASSERT_EQUAL_UINT8(3, bi.channel);
}

void test_a_built_hidden_beacon_parses_back_as_hidden_rather_than_absent() {
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "", kAp, 1, BeaconSecurity::Open, s);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    BeaconInfo bi;
    TEST_ASSERT_TRUE(parseBeacon(f + fi.headerLen, n - fi.headerLen, bi));
    TEST_ASSERT_TRUE(bi.ssidPresent);   // the element is there
    TEST_ASSERT_TRUE(bi.ssidHidden);    // and it is empty
}

// ---- invented addresses -----------------------------------------------------

void test_an_invented_address_was_never_assigned_to_anybody() {
    // An address generated at random across the whole space lands on real
    // OUIs, so a flood would attribute hundreds of frames to a manufacturer
    // who had nothing to do with it -- and anyone reading the capture
    // afterwards would believe it.
    for (uint32_t salt = 0; salt < 500; salt++) {
        uint8_t a[6];
        inventedAddress(a, salt);
        TEST_ASSERT_TRUE((a[0] & 0x02) != 0);   // locally administered
        TEST_ASSERT_TRUE((a[0] & 0x01) == 0);   // individual, not a group
        TEST_ASSERT_TRUE(addressIsInvented(a));
    }
}

void test_invented_addresses_are_distinct_and_reproducible() {
    uint8_t a[6], b[6], again[6];
    inventedAddress(a, 1);
    inventedAddress(b, 2);
    inventedAddress(again, 1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a, again, 6);
    TEST_ASSERT_TRUE(std::memcmp(a, b, 6) != 0);
}

void test_consecutive_salts_do_not_look_like_a_counter() {
    // A swarm whose addresses differ only in the last byte is a counter, and
    // anything watching can spot it as one.
    uint8_t a[6], b[6];
    inventedAddress(a, 100);
    inventedAddress(b, 101);
    int differing = 0;
    for (int i = 0; i < 6; i++) if (a[i] != b[i]) differing++;
    TEST_ASSERT_TRUE(differing >= 3);
}

void test_a_real_assigned_address_is_not_called_invented() {
    const uint8_t apple[6] = {0x3C, 0x22, 0xFB, 0x01, 0x02, 0x03};
    TEST_ASSERT_FALSE(addressIsInvented(apple));
    const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    TEST_ASSERT_FALSE(addressIsInvented(broadcast));
    TEST_ASSERT_FALSE(addressIsInvented(nullptr));
}

void test_an_invented_address_can_be_a_beacons_bssid() {
    uint8_t bssid[6];
    inventedAddress(bssid, 7);
    uint8_t f[kInjectMax];
    Sequencer s;
    const size_t n = buildBeacon(f, sizeof(f), "ORTHRUS-7", bssid, 1,
                                 BeaconSecurity::Open, s);
    TEST_ASSERT_TRUE(n > 0);
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f, n, fi));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(bssid, fi.addr3, 6);
    TEST_ASSERT_TRUE(addressIsInvented(fi.addr3));
}

int main() {
    UNITY_BEGIN();

    RUN_TEST(test_a_deauth_is_twenty_six_bytes_laid_out_as_the_standard_says);
    RUN_TEST(test_a_disassoc_differs_from_a_deauth_only_in_its_subtype);
    RUN_TEST(test_the_source_is_separate_from_the_bssid_so_both_directions_can_be_sent);
    RUN_TEST(test_every_reason_code_reaches_the_frame_intact);

    RUN_TEST(test_sequence_numbers_advance_rather_than_repeating_forever);
    RUN_TEST(test_the_sequence_number_wraps_at_twelve_bits);
    RUN_TEST(test_the_fragment_number_is_always_zero);
    RUN_TEST(test_one_sequencer_is_shared_across_frame_shapes);

    RUN_TEST(test_a_beacon_carries_its_name_channel_and_rates);
    RUN_TEST(test_an_open_beacon_does_not_set_the_privacy_bit_and_carries_no_rsn);
    RUN_TEST(test_a_wpa2_beacon_sets_privacy_and_advertises_psk_with_ccmp);
    RUN_TEST(test_a_wpa3_beacon_advertises_sae_and_requires_protected_management);
    RUN_TEST(test_an_empty_name_produces_a_hidden_network_beacon);
    RUN_TEST(test_an_overlong_name_is_truncated_rather_than_refused);

    RUN_TEST(test_a_csa_beacon_carries_the_switch_element_with_mode_one);
    RUN_TEST(test_a_csa_beacon_still_claims_the_channel_it_is_sitting_on);

    RUN_TEST(test_a_probe_response_is_addressed_to_the_station_that_asked);

    RUN_TEST(test_an_auth_request_is_open_system_transaction_one);
    RUN_TEST(test_an_assoc_request_asks_for_psk_so_a_pmkid_can_be_volunteered);

    RUN_TEST(test_a_buffer_too_small_writes_nothing_rather_than_a_partial_frame);
    RUN_TEST(test_a_beacon_that_would_not_fit_writes_nothing);
    RUN_TEST(test_a_null_argument_is_refused);
    RUN_TEST(test_a_null_ssid_is_a_hidden_network_rather_than_a_refusal);
    RUN_TEST(test_every_builder_stays_inside_the_declared_maximum);

    RUN_TEST(test_a_built_deauth_parses_back_as_a_deauth);
    RUN_TEST(test_a_built_beacon_parses_back_with_the_name_and_security_it_was_given);
    RUN_TEST(test_a_built_wpa3_beacon_parses_back_as_requiring_protected_management);
    RUN_TEST(test_a_built_open_beacon_parses_back_with_no_rsn_at_all);
    RUN_TEST(test_a_built_csa_beacon_parses_back_without_being_called_truncated);
    RUN_TEST(test_a_built_probe_response_parses_back_as_one);
    RUN_TEST(test_a_built_hidden_beacon_parses_back_as_hidden_rather_than_absent);

    RUN_TEST(test_an_invented_address_was_never_assigned_to_anybody);
    RUN_TEST(test_invented_addresses_are_distinct_and_reproducible);
    RUN_TEST(test_consecutive_salts_do_not_look_like_a_counter);
    RUN_TEST(test_a_real_assigned_address_is_not_called_invented);
    RUN_TEST(test_an_invented_address_can_be_a_beacons_bssid);

    return UNITY_END();
}
