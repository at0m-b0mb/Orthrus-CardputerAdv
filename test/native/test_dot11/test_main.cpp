// Host tests for the 802.11 / EAPOL capture engine.
//
// Every byte offset in here is defined by somebody else's standard, and a wrong
// one does not throw -- it produces a device that listens forever and finds
// nothing, or a file that a cracker rejects without saying why. So the tests
// build real frame bytes and assert on them, rather than trusting the parser to
// agree with itself.

#include <unity.h>

#include <cstdio>
#include <cstring>
#include <initializer_list>

#include "dot11/capture.h"
#include "dot11/eapol.h"
#include "dot11/frame.h"
#include "dot11/hashline.h"

using namespace orthrus::dot11;

namespace {

const uint8_t kAp[6]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t kSta[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
const uint8_t kBcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ---- frame builders ---------------------------------------------------------

struct Frame {
    uint8_t buf[512] = {0};
    size_t  len      = 0;

    void u8(uint8_t v) { buf[len++] = v; }
    void mac(const uint8_t m[6]) { std::memcpy(buf + len, m, 6); len += 6; }
    void bytes(const uint8_t* p, size_t n) { std::memcpy(buf + len, p, n); len += n; }
};

// A MAC header. `fc1` carries the ToDS/FromDS/protected/order bits.
void header(Frame& f, uint8_t type, uint8_t subtype, uint8_t fc1,
            const uint8_t a1[6], const uint8_t a2[6], const uint8_t a3[6]) {
    f.u8(static_cast<uint8_t>(((subtype & 0x0F) << 4) | ((type & 0x03) << 2)));
    f.u8(fc1);
    f.u8(0); f.u8(0);          // duration
    f.mac(a1);
    f.mac(a2);
    f.mac(a3);
    f.u8(0); f.u8(0);          // sequence control
}

// One 802.1X EAPOL-Key payload, built field by field at the real offsets.
struct KeyBuilder {
    uint8_t  descriptor   = 2;
    uint16_t keyInfo      = 0;
    uint64_t replay       = 0;
    uint8_t  nonceFill    = 0;
    uint8_t  micFill      = 0;
    uint8_t  keyData[128] = {0};
    uint16_t keyDataLen   = 0;
    bool     lieAboutLength = false;

    size_t build(uint8_t* out) const {
        const size_t total = 99 + keyDataLen;
        std::memset(out, 0, total);
        out[0] = 2;                       // EAPOL version
        out[1] = 3;                       // EAPOL-Key
        const uint16_t body = lieAboutLength
                                  ? 1
                                  : static_cast<uint16_t>(95 + keyDataLen);
        out[2] = static_cast<uint8_t>(body >> 8);
        out[3] = static_cast<uint8_t>(body & 0xFF);
        out[4] = descriptor;
        out[5] = static_cast<uint8_t>(keyInfo >> 8);
        out[6] = static_cast<uint8_t>(keyInfo & 0xFF);
        for (int i = 0; i < 8; i++)
            out[9 + i] = static_cast<uint8_t>((replay >> (56 - 8 * i)) & 0xFF);
        if (nonceFill) std::memset(out + 17, nonceFill, 32);
        if (micFill) std::memset(out + 81, micFill, 16);
        out[97] = static_cast<uint8_t>(keyDataLen >> 8);
        out[98] = static_cast<uint8_t>(keyDataLen & 0xFF);
        if (keyDataLen) std::memcpy(out + 99, keyData, keyDataLen);
        return total;
    }
};

KeyBuilder m1(uint64_t rc = 1) {
    KeyBuilder k;
    k.keyInfo   = kKeyInfoPairwise | kKeyInfoAck | 0x0002;  // ACK, no MIC
    k.replay    = rc;
    k.nonceFill = 0xA1;
    return k;
}

KeyBuilder m2(uint64_t rc = 1) {
    KeyBuilder k;
    k.keyInfo   = kKeyInfoPairwise | kKeyInfoMic | 0x0002;  // MIC, no ACK, not secure
    k.replay    = rc;
    k.nonceFill = 0x52;
    k.micFill   = 0xCD;
    // M2 carries the client's RSN element: that presence is part of how M2 is
    // told apart from M4.
    k.keyDataLen  = 22;
    k.keyData[0]  = 0x30;
    k.keyData[1]  = 0x14;
    return k;
}

KeyBuilder m3(uint64_t rc = 2) {
    KeyBuilder k;
    k.keyInfo   = kKeyInfoPairwise | kKeyInfoAck | kKeyInfoMic | kKeyInfoSecure |
                  kKeyInfoInstall | kKeyInfoEncrypted | 0x0002;
    k.replay    = rc;
    k.nonceFill = 0xA1;   // the SAME anonce the AP sent in M1
    k.micFill   = 0x3B;
    k.keyDataLen = 40;
    return k;
}

KeyBuilder m4(uint64_t rc = 2) {
    KeyBuilder k;
    k.keyInfo = kKeyInfoPairwise | kKeyInfoMic | kKeyInfoSecure | 0x0002;
    k.replay  = rc;
    k.micFill = 0x77;
    return k;   // no nonce, no key data
}

KeyFrame parsed(const KeyBuilder& kb, uint8_t* scratch) {
    const size_t n = kb.build(scratch);
    KeyFrame kf;
    TEST_ASSERT_TRUE(parseKeyFrame(scratch, n, kf));
    return kf;
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- the header length trap -------------------------------------------------

void test_plain_data_header_is_24_bytes() {
    Frame f;
    header(f, 2, 0x00, 0x01, kAp, kSta, kAp);
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    TEST_ASSERT_EQUAL_UINT16(24, fi.headerLen);
}

void test_qos_data_header_carries_two_extra_bytes() {
    // Subtype 0x08 is QoS Data. Reading the payload at offset 24 instead of 26
    // is the single most common way an 802.11 sniffer finds no EAPOL at all.
    Frame f;
    header(f, 2, 0x08, 0x01, kAp, kSta, kAp);
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    TEST_ASSERT_EQUAL_UINT16(26, fi.headerLen);
}

void test_four_address_frame_adds_addr4() {
    Frame f;
    header(f, 2, 0x00, 0x03, kAp, kSta, kAp);  // ToDS and FromDS
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    TEST_ASSERT_EQUAL_UINT16(30, fi.headerLen);
}

void test_ordered_qos_data_adds_ht_control() {
    Frame f;
    header(f, 2, 0x08, 0x01 | 0x80, kAp, kSta, kAp);  // ToDS + order
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    TEST_ASSERT_EQUAL_UINT16(30, fi.headerLen);
}

void test_ordered_management_frame_does_not_add_ht_control() {
    // The order bit means "strictly ordered" on a management frame and has
    // nothing to do with HT control. Adding four bytes here would shift every
    // beacon element by four and lose every SSID.
    Frame f;
    header(f, 0, kSubtypeBeacon, 0x80, kBcast, kAp, kAp);
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    TEST_ASSERT_EQUAL_UINT16(24, fi.headerLen);
}

void test_short_buffer_is_rejected_not_read_past() {
    uint8_t tiny[10] = {0};
    FrameInfo fi;
    TEST_ASSERT_FALSE(parseHeader(tiny, sizeof(tiny), fi));
    TEST_ASSERT_FALSE(parseHeader(nullptr, 1000, fi));
}

void test_qos_frame_shorter_than_its_own_header_is_rejected() {
    Frame f;
    header(f, 2, 0x08, 0x01, kAp, kSta, kAp);
    f.len = 25;   // claims QoS, but there is no room for the QoS field
    FrameInfo fi;
    TEST_ASSERT_FALSE(parseHeader(f.buf, f.len, fi));
}

// ---- which address is the access point --------------------------------------

void test_uplink_frame_puts_bssid_in_addr1() {
    Frame f;
    header(f, 2, 0x00, 0x01, kAp, kSta, kBcast);  // ToDS
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    uint8_t bssid[6], sta[6];
    TEST_ASSERT_TRUE(resolveEndpoints(fi, bssid, sta));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, bssid, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, sta, 6);
}

void test_downlink_frame_puts_bssid_in_addr2() {
    // The mirror image. Getting this wrong files every AP-to-client message
    // under a target keyed the wrong way round, and the two halves of a
    // handshake never meet.
    Frame f;
    header(f, 2, 0x00, 0x02, kSta, kAp, kBcast);  // FromDS
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    uint8_t bssid[6], sta[6];
    TEST_ASSERT_TRUE(resolveEndpoints(fi, bssid, sta));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, bssid, 6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, sta, 6);
}

void test_wds_frame_has_no_single_station() {
    Frame f;
    header(f, 2, 0x00, 0x03, kAp, kSta, kBcast);
    f.len = 64;
    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    uint8_t bssid[6], sta[6];
    TEST_ASSERT_FALSE(resolveEndpoints(fi, bssid, sta));
}

void test_group_addresses_are_not_stations() {
    TEST_ASSERT_TRUE(macIsGroup(kBcast));
    const uint8_t multicast[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
    TEST_ASSERT_TRUE(macIsGroup(multicast));
    const uint8_t zero[6] = {0};
    TEST_ASSERT_TRUE(macIsGroup(zero));
    TEST_ASSERT_FALSE(macIsGroup(kSta));
}

// ---- beacons ----------------------------------------------------------------

void test_beacon_yields_ssid_and_channel() {
    uint8_t body[64] = {0};
    size_t n = 12;                      // fixed parameters
    body[n++] = 0x00; body[n++] = 6;    // SSID element
    std::memcpy(body + n, "office", 6); n += 6;
    body[n++] = 0x03; body[n++] = 1; body[n++] = 11;   // DS parameter set
    body[n++] = 0x30; body[n++] = 2; body[n++] = 0x01; body[n++] = 0x00;  // RSN

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_EQUAL_STRING("office", b.ssid);
    TEST_ASSERT_TRUE(b.ssidPresent);
    TEST_ASSERT_FALSE(b.ssidHidden);
    TEST_ASSERT_EQUAL_UINT8(11, b.channel);
    TEST_ASSERT_TRUE(b.hasRsn);
    TEST_ASSERT_FALSE(b.truncated);
}

void test_nul_padded_ssid_counts_as_hidden() {
    // A hidden AP may send a zero-length SSID or one padded with NULs. Both
    // mean the same thing, and a parser that only handles the first shows a
    // network named "" alongside one named "\0\0\0\0".
    uint8_t body[64] = {0};
    size_t n = 12;
    body[n++] = 0x00; body[n++] = 4;
    n += 4;   // four NULs

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_TRUE(b.ssidPresent);
    TEST_ASSERT_TRUE(b.ssidHidden);
    TEST_ASSERT_EQUAL_STRING("", b.ssid);
}

void test_element_running_past_the_end_is_flagged_not_read() {
    uint8_t body[32] = {0};
    size_t n = 12;
    body[n++] = 0x00; body[n++] = 200;  // claims 200 bytes, buffer has a few
    n += 4;

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_TRUE(b.truncated);
    TEST_ASSERT_FALSE(b.ssidPresent);
}

void test_oversized_ssid_is_clamped_to_32_bytes() {
    uint8_t body[128] = {0};
    size_t n = 12;
    body[n++] = 0x00; body[n++] = 40;   // longer than the standard allows
    std::memset(body + n, 'x', 40); n += 40;

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_EQUAL_size_t(32, std::strlen(b.ssid));
}

void test_vendor_wpa_element_is_recognised() {
    uint8_t body[32] = {0};
    size_t n = 12;
    body[n++] = 0xDD; body[n++] = 4;
    body[n++] = 0x00; body[n++] = 0x50; body[n++] = 0xF2; body[n++] = 0x01;

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_TRUE(b.hasWpa);
    TEST_ASSERT_FALSE(b.hasRsn);
}


// ---- RSN: the field that decides whether a deauth can work -------------------

namespace {

// Builds an RSN element body: version, group cipher, pairwise list, AKM list,
// capabilities. The capabilities can only be found by walking the two
// variable-length lists in front of them, which is the whole point.
struct RsnBuilder {
    uint8_t buf[64] = {0};
    size_t  len     = 0;

    RsnBuilder() { u16(1); suite(4); }          // version 1, group cipher CCMP

    void u16(uint16_t v) {
        buf[len++] = static_cast<uint8_t>(v & 0xFF);
        buf[len++] = static_cast<uint8_t>(v >> 8);
    }
    void suite(uint8_t type) {
        buf[len++] = 0x00; buf[len++] = 0x0F; buf[len++] = 0xAC; buf[len++] = type;
    }
    void pairwise(std::initializer_list<uint8_t> types) {
        u16(static_cast<uint16_t>(types.size()));
        for (uint8_t t : types) suite(t);
    }
    void akm(std::initializer_list<uint8_t> types) {
        u16(static_cast<uint16_t>(types.size()));
        for (uint8_t t : types) suite(t);
    }
    void caps(uint16_t v) { u16(v); }
};

}  // namespace

void test_pmf_required_is_read_past_the_variable_length_suite_lists() {
    // Reading the capabilities from a fixed offset gets the right answer on a
    // typical access point and the wrong one on anything unusual. Two pairwise
    // ciphers and three AKMs move the field by twenty bytes.
    RsnBuilder b;
    b.pairwise({4, 8});
    b.akm({2, 6, 8});
    b.caps(0x00C0);   // MFPC | MFPR

    RsnInfo r;
    TEST_ASSERT_TRUE(parseRsn(b.buf, b.len, r));
    TEST_ASSERT_TRUE(r.present);
    TEST_ASSERT_TRUE(r.pmfRequired);
    TEST_ASSERT_TRUE(r.pmfCapable);
    TEST_ASSERT_TRUE(r.akmSae);
    TEST_ASSERT_TRUE(r.akmPsk);
    TEST_ASSERT_TRUE(r.cipherCcmp);
    TEST_ASSERT_TRUE(r.cipherGcmp);
    TEST_ASSERT_FALSE(r.malformed);
}

void test_a_network_with_no_pmf_bits_reports_neither() {
    RsnBuilder b;
    b.pairwise({4});
    b.akm({2});
    b.caps(0x0000);

    RsnInfo r;
    TEST_ASSERT_TRUE(parseRsn(b.buf, b.len, r));
    TEST_ASSERT_FALSE(r.pmfCapable);
    TEST_ASSERT_FALSE(r.pmfRequired);
}

void test_pmf_required_implies_capable() {
    // Some access points set only the required bit. Reporting such a network as
    // "not capable" would be absurd.
    RsnBuilder b;
    b.pairwise({4});
    b.akm({8});
    b.caps(0x0040);   // MFPR only

    RsnInfo r;
    TEST_ASSERT_TRUE(parseRsn(b.buf, b.len, r));
    TEST_ASSERT_TRUE(r.pmfRequired);
    TEST_ASSERT_TRUE(r.pmfCapable);
}

void test_a_suite_count_running_past_the_end_reports_malformed_not_pmf() {
    // A beacon built to confuse the parser must not end up claiming protection
    // the network does not have, nor denying protection it does.
    RsnBuilder b;
    b.u16(40);        // claims forty pairwise ciphers
    b.suite(4);

    RsnInfo r;
    TEST_ASSERT_TRUE(parseRsn(b.buf, b.len, r));
    TEST_ASSERT_TRUE(r.malformed);
    TEST_ASSERT_FALSE(r.pmfRequired);
    TEST_ASSERT_FALSE(r.pmfCapable);
}

void test_a_truncated_rsn_element_stops_cleanly() {
    RsnBuilder b;              // version and group cipher only
    RsnInfo r;
    TEST_ASSERT_TRUE(parseRsn(b.buf, b.len, r));
    TEST_ASSERT_TRUE(r.present);
    TEST_ASSERT_FALSE(r.pmfRequired);

    RsnInfo tiny;
    TEST_ASSERT_FALSE(parseRsn(b.buf, 1, tiny));
    TEST_ASSERT_FALSE(parseRsn(nullptr, 40, tiny));
}

void test_vendor_suites_are_skipped_not_misread() {
    // A selector with somebody else's OUI means something we do not know. Its
    // type byte must not be read as though it were an IEEE one.
    RsnBuilder b;
    b.u16(1);
    b.buf[b.len++] = 0x00; b.buf[b.len++] = 0x50;
    b.buf[b.len++] = 0xF2; b.buf[b.len++] = 0x08;   // vendor OUI, type 8
    b.akm({2});
    b.caps(0x0080);

    RsnInfo r;
    TEST_ASSERT_TRUE(parseRsn(b.buf, b.len, r));
    TEST_ASSERT_FALSE(r.cipherGcmp);   // type 8 under a vendor OUI is not GCMP
    TEST_ASSERT_TRUE(r.pmfCapable);
}

void test_beacon_carries_the_rsn_details_through() {
    RsnBuilder rsn;
    rsn.pairwise({4});
    rsn.akm({8});
    rsn.caps(0x00C0);

    uint8_t body[128] = {0};
    size_t n = 12;
    body[n++] = 0x00; body[n++] = 4;
    std::memcpy(body + n, "corp", 4); n += 4;
    body[n++] = 0x30; body[n++] = static_cast<uint8_t>(rsn.len);
    std::memcpy(body + n, rsn.buf, rsn.len); n += rsn.len;

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_TRUE(b.hasRsn);
    TEST_ASSERT_TRUE(b.rsn.pmfRequired);
    TEST_ASSERT_TRUE(b.rsn.akmSae);
}

void test_wps_is_told_apart_from_the_old_wpa_element() {
    // Both are Microsoft OUI 00-50-F2 and differ only in the type byte.
    uint8_t body[32] = {0};
    size_t n = 12;
    body[n++] = 0xDD; body[n++] = 4;
    body[n++] = 0x00; body[n++] = 0x50; body[n++] = 0xF2; body[n++] = 0x04;

    BeaconInfo b;
    TEST_ASSERT_TRUE(parseBeacon(body, n, b));
    TEST_ASSERT_TRUE(b.hasWps);
    TEST_ASSERT_FALSE(b.hasWpa);
}

// ---- finding the EAPOL payload ---------------------------------------------

void test_eapol_payload_found_over_llc_snap() {
    Frame f;
    header(f, 2, 0x08, 0x01, kAp, kSta, kAp);   // QoS data, uplink
    f.u8(0); f.u8(0);                            // QoS control
    const uint8_t snap[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    f.bytes(snap, 8);
    const uint8_t marker[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    f.bytes(marker, 4);

    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    const uint8_t* p = nullptr;
    size_t plen = 0;
    TEST_ASSERT_TRUE(eapolPayload(f.buf, f.len, fi, &p, &plen));
    TEST_ASSERT_EQUAL_size_t(4, plen);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(marker, p, 4);
}

void test_protected_frame_is_never_treated_as_eapol() {
    // A protected frame is ciphertext. Parsing it as a key frame would feed
    // random bytes to the nonce and MIC fields and occasionally look valid.
    Frame f;
    header(f, 2, 0x00, 0x01 | 0x40, kAp, kSta, kAp);
    const uint8_t snap[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    f.bytes(snap, 8);
    f.len += 20;

    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    const uint8_t* p = nullptr;
    size_t plen = 0;
    TEST_ASSERT_FALSE(eapolPayload(f.buf, f.len, fi, &p, &plen));
}

void test_non_eapol_ethertype_is_ignored() {
    Frame f;
    header(f, 2, 0x00, 0x01, kAp, kSta, kAp);
    const uint8_t snapIp[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    f.bytes(snapIp, 8);
    f.len += 20;

    FrameInfo fi;
    TEST_ASSERT_TRUE(parseHeader(f.buf, f.len, fi));
    const uint8_t* p = nullptr;
    size_t plen = 0;
    TEST_ASSERT_FALSE(eapolPayload(f.buf, f.len, fi, &p, &plen));
}

// ---- EAPOL-Key --------------------------------------------------------------

void test_messages_are_classified_from_the_key_info_bits() {
    uint8_t buf[256];
    TEST_ASSERT_EQUAL(static_cast<int>(Message::M1),
                      static_cast<int>(parsed(m1(), buf).message));
    TEST_ASSERT_EQUAL(static_cast<int>(Message::M2),
                      static_cast<int>(parsed(m2(), buf).message));
    TEST_ASSERT_EQUAL(static_cast<int>(Message::M3),
                      static_cast<int>(parsed(m3(), buf).message));
    TEST_ASSERT_EQUAL(static_cast<int>(Message::M4),
                      static_cast<int>(parsed(m4(), buf).message));
}

void test_m2_and_m4_are_told_apart_by_secure_and_key_data() {
    // They differ in exactly two bits' worth of evidence. Storing an M4 as an
    // M2 yields a hash line with the wrong EAPOL bytes, which exports happily
    // and never cracks.
    uint8_t buf[256];

    KeyBuilder wpa1M4;                       // original WPA: Secure may be clear
    wpa1M4.descriptor = kDescriptorWpa;
    wpa1M4.keyInfo    = kKeyInfoPairwise | kKeyInfoMic | 0x0001;
    wpa1M4.micFill    = 0x11;
    wpa1M4.keyDataLen = 0;                   // ... but M4 carries nothing
    TEST_ASSERT_EQUAL(static_cast<int>(Message::M4),
                      static_cast<int>(parsed(wpa1M4, buf).message));

    KeyBuilder wpa1M2 = wpa1M4;
    wpa1M2.keyDataLen = 22;                  // M2 carries the client's element
    TEST_ASSERT_EQUAL(static_cast<int>(Message::M2),
                      static_cast<int>(parsed(wpa1M2, buf).message));
}

void test_group_key_handshake_is_not_mistaken_for_the_four_way() {
    uint8_t buf[256];
    KeyBuilder g;
    g.keyInfo = kKeyInfoAck | kKeyInfoMic | kKeyInfoSecure | 0x0002;  // no pairwise bit
    g.micFill = 0x22;
    TEST_ASSERT_EQUAL(static_cast<int>(Message::Unknown),
                      static_cast<int>(parsed(g, buf).message));
}

void test_replay_counter_is_read_big_endian() {
    uint8_t buf[256];
    const KeyFrame kf = parsed(m1(0x0102030405060708ull), buf);
    TEST_ASSERT_EQUAL_UINT64(0x0102030405060708ull, kf.replayCounter);
}

void test_disagreeing_length_fields_are_rejected() {
    // Two independent length claims in the same frame. When they disagree, one
    // of them is a lie, and we do not get to choose which.
    uint8_t buf[256];
    KeyBuilder k = m2();
    k.lieAboutLength = true;
    const size_t n = k.build(buf);
    KeyFrame kf;
    TEST_ASSERT_FALSE(parseKeyFrame(buf, n, kf));
}

void test_key_data_longer_than_the_buffer_is_rejected() {
    uint8_t buf[256];
    KeyBuilder k = m2();
    const size_t n = k.build(buf);
    buf[97] = 0x10;   // claim 4096 bytes of key data
    buf[98] = 0x00;
    KeyFrame kf;
    TEST_ASSERT_FALSE(parseKeyFrame(buf, n, kf));
}

void test_truncated_and_non_key_payloads_are_rejected() {
    uint8_t buf[256] = {0};
    KeyFrame kf;
    TEST_ASSERT_FALSE(parseKeyFrame(buf, 40, kf));       // shorter than the header
    TEST_ASSERT_FALSE(parseKeyFrame(nullptr, 200, kf));

    KeyBuilder k = m1();
    const size_t n = k.build(buf);
    buf[1] = 1;                                          // EAPOL-Start, not Key
    TEST_ASSERT_FALSE(parseKeyFrame(buf, n, kf));
}

// ---- PMKID ------------------------------------------------------------------

void test_pmkid_is_lifted_out_of_the_m1_key_data() {
    uint8_t buf[256];
    KeyBuilder k = m1();
    k.keyDataLen = 22;
    k.keyData[0] = 0xDD; k.keyData[1] = 0x14;
    k.keyData[2] = 0x00; k.keyData[3] = 0x0F; k.keyData[4] = 0xAC; k.keyData[5] = 0x04;
    for (int i = 0; i < 16; i++) k.keyData[6 + i] = static_cast<uint8_t>(0xF0 + i);

    const KeyFrame kf = parsed(k, buf);
    uint8_t pmkid[16];
    TEST_ASSERT_TRUE(extractPmkid(kf, pmkid));
    for (int i = 0; i < 16; i++)
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(0xF0 + i), pmkid[i]);
}

void test_all_zero_pmkid_is_reported_as_absent() {
    // Some access points emit a zero-filled KDE as a placeholder. Exporting it
    // costs the operator a cracker run against nothing.
    uint8_t buf[256];
    KeyBuilder k = m1();
    k.keyDataLen = 22;
    k.keyData[0] = 0xDD; k.keyData[1] = 0x14;
    k.keyData[2] = 0x00; k.keyData[3] = 0x0F; k.keyData[4] = 0xAC; k.keyData[5] = 0x04;

    const KeyFrame kf = parsed(k, buf);
    uint8_t pmkid[16];
    TEST_ASSERT_FALSE(extractPmkid(kf, pmkid));
}

void test_pmkid_is_not_hunted_for_in_encrypted_key_data() {
    uint8_t buf[256];
    KeyBuilder k = m1();
    k.keyInfo |= kKeyInfoEncrypted;
    k.keyDataLen = 22;
    k.keyData[0] = 0xDD; k.keyData[1] = 0x14;
    k.keyData[2] = 0x00; k.keyData[3] = 0x0F; k.keyData[4] = 0xAC; k.keyData[5] = 0x04;
    for (int i = 0; i < 16; i++) k.keyData[6 + i] = 0x5A;

    const KeyFrame kf = parsed(k, buf);
    uint8_t pmkid[16];
    TEST_ASSERT_FALSE(extractPmkid(kf, pmkid));
}

void test_pmkid_kde_running_past_the_key_data_is_rejected() {
    uint8_t buf[256];
    KeyBuilder k = m1();
    k.keyDataLen = 8;
    k.keyData[0] = 0xDD; k.keyData[1] = 0x14;   // claims 20 bytes, has 6
    k.keyData[2] = 0x00; k.keyData[3] = 0x0F; k.keyData[4] = 0xAC; k.keyData[5] = 0x04;

    const KeyFrame kf = parsed(k, buf);
    uint8_t pmkid[16];
    TEST_ASSERT_FALSE(extractPmkid(kf, pmkid));
}

void test_other_kdes_are_skipped_to_reach_the_pmkid() {
    uint8_t buf[256];
    KeyBuilder k = m1();
    size_t n = 0;
    k.keyData[n++] = 0x30; k.keyData[n++] = 4;            // an RSN element first
    n += 4;
    k.keyData[n++] = 0xDD; k.keyData[n++] = 0x06;         // a vendor KDE that is not ours
    k.keyData[n++] = 0x00; k.keyData[n++] = 0x0F;
    k.keyData[n++] = 0xAC; k.keyData[n++] = 0x01;
    n += 2;
    k.keyData[n++] = 0xDD; k.keyData[n++] = 0x14;         // and then the PMKID
    k.keyData[n++] = 0x00; k.keyData[n++] = 0x0F;
    k.keyData[n++] = 0xAC; k.keyData[n++] = 0x04;
    for (int i = 0; i < 16; i++) k.keyData[n++] = 0x9C;
    k.keyDataLen = static_cast<uint16_t>(n);

    const KeyFrame kf = parsed(k, buf);
    uint8_t pmkid[16];
    TEST_ASSERT_TRUE(extractPmkid(kf, pmkid));
    TEST_ASSERT_EQUAL_UINT8(0x9C, pmkid[0]);
}

void test_pmkid_is_only_taken_from_m1() {
    uint8_t buf[256];
    const KeyFrame kf = parsed(m2(), buf);
    uint8_t pmkid[16];
    TEST_ASSERT_FALSE(extractPmkid(kf, pmkid));
}

// ---- pairing ----------------------------------------------------------------

namespace {

// A table is ~7 KB. Static, for exactly the reason the header warns about.
Table& table() {
    static Table t;
    return t;
}

void feed(Table& t, const KeyBuilder& kb, uint32_t nowMs = 100) {
    uint8_t buf[256];
    const size_t n = kb.build(buf);
    KeyFrame kf;
    TEST_ASSERT_TRUE(parseKeyFrame(buf, n, kf));
    t.ingest(kAp, kSta, kf, buf, n, 6, -50, nowMs);
}

}  // namespace

void test_m1_and_m2_with_matching_counters_pair_cleanly() {
    Table& t = table();
    t.clear();
    feed(t, m1(7));
    feed(t, m2(7));

    TEST_ASSERT_EQUAL_UINT8(1, t.count());
    uint8_t pair = 0xFF;
    TEST_ASSERT_TRUE(t.at(0).messagePair(pair));
    TEST_ASSERT_EQUAL_UINT8(kPairM1M2, pair);
    TEST_ASSERT_EQUAL(static_cast<int>(Quality::Handshake),
                      static_cast<int>(t.at(0).quality()));
}

void test_m2_and_m3_pair_when_the_counter_steps_up_by_one() {
    // M3 is the AP's reply to M2, so its counter is the next one -- equality
    // would be the wrong check here and would reject every real M2+M3.
    Table& t = table();
    t.clear();
    feed(t, m2(11));
    feed(t, m3(12));

    uint8_t pair = 0xFF;
    TEST_ASSERT_TRUE(t.at(0).messagePair(pair));
    TEST_ASSERT_EQUAL_UINT8(kPairM2M3, pair);
}

void test_mismatched_counters_still_export_but_are_flagged() {
    Table& t = table();
    t.clear();
    feed(t, m1(3));
    feed(t, m2(9));

    uint8_t pair = 0;
    TEST_ASSERT_TRUE(t.at(0).messagePair(pair));
    TEST_ASSERT_TRUE((pair & kPairNotReplayChecked) != 0);
    TEST_ASSERT_EQUAL_UINT8(kPairM1M2, pair & 0x0F);
}

void test_m2_alone_is_not_a_handshake() {
    Table& t = table();
    t.clear();
    feed(t, m2(1));

    uint8_t pair = 0;
    TEST_ASSERT_FALSE(t.at(0).messagePair(pair));
    TEST_ASSERT_EQUAL(static_cast<int>(Quality::Fragment),
                      static_cast<int>(t.at(0).quality()));
}

void test_m1_and_m3_without_m2_is_not_a_handshake() {
    // Both AP-side messages, no client reply: nothing to compute a MIC over.
    Table& t = table();
    t.clear();
    feed(t, m1(4));
    feed(t, m3(5));

    uint8_t pair = 0;
    TEST_ASSERT_FALSE(t.at(0).messagePair(pair));
}

void test_the_stored_eapol_blob_has_its_mic_zeroed() {
    // Both endpoints computed the MIC over the frame with this field zeroed.
    // Exporting the frame as received produces a hash nobody can reproduce.
    Table& t = table();
    t.clear();
    feed(t, m2(2));

    const Target& target = t.at(0);
    TEST_ASSERT_TRUE(target.eapolLen >= kMicOffset + kMicLen);
    for (size_t i = 0; i < kMicLen; i++)
        TEST_ASSERT_EQUAL_UINT8(0, target.eapol[kMicOffset + i]);
    // ... while the MIC itself is kept alongside, intact.
    TEST_ASSERT_EQUAL_UINT8(0xCD, target.mic[0]);
}

void test_the_anonce_from_m3_is_used_when_m1_was_missed() {
    // M1 is the frame most often missed: it goes past while the radio is still
    // hopping onto the channel. M3 carries the same anonce, and taking it is
    // what turns a half-heard handshake into a usable one.
    Table& t = table();
    t.clear();
    feed(t, m2(11));
    feed(t, m3(12));

    const Target& target = t.at(0);
    TEST_ASSERT_TRUE(target.haveAnonce);
    TEST_ASSERT_FALSE(target.anonceFromM1);
    TEST_ASSERT_EQUAL_UINT8(0xA1, target.anonce[0]);
}

void test_targets_are_keyed_on_the_ap_and_station_pair() {
    // One AP runs a separate handshake with every client. Merging two of them
    // produces a line whose nonce and MIC come from different conversations.
    Table& t = table();
    t.clear();

    uint8_t buf[256];
    KeyFrame kf;

    KeyBuilder a = m2(1);
    size_t n = a.build(buf);
    TEST_ASSERT_TRUE(parseKeyFrame(buf, n, kf));
    t.ingest(kAp, kSta, kf, buf, n, 6, -50, 10);

    const uint8_t other[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
    KeyBuilder b = m2(1);
    n = b.build(buf);
    TEST_ASSERT_TRUE(parseKeyFrame(buf, n, kf));
    t.ingest(kAp, other, kf, buf, n, 6, -50, 11);

    TEST_ASSERT_EQUAL_UINT8(2, t.count());
}

void test_group_and_self_addressed_frames_are_refused() {
    Table& t = table();
    t.clear();

    uint8_t buf[256];
    KeyBuilder k = m2();
    const size_t n = k.build(buf);
    KeyFrame kf;
    TEST_ASSERT_TRUE(parseKeyFrame(buf, n, kf));

    TEST_ASSERT_NULL(t.ingest(kAp, kBcast, kf, buf, n, 6, -50, 1));
    TEST_ASSERT_NULL(t.ingest(kBcast, kSta, kf, buf, n, 6, -50, 1));
    TEST_ASSERT_NULL(t.ingest(kAp, kAp, kf, buf, n, 6, -50, 1));
    TEST_ASSERT_EQUAL_UINT8(0, t.count());
}

void test_a_full_table_counts_what_it_drops() {
    // A silent cap looks exactly like a quiet radio, which is the one thing an
    // operator must never have to guess about.
    Table& t = table();
    t.clear();

    uint8_t buf[256];
    KeyBuilder k = m2();
    const size_t n = k.build(buf);
    KeyFrame kf;
    TEST_ASSERT_TRUE(parseKeyFrame(buf, n, kf));

    for (int i = 0; i < Table::kMaxTargets + 4; i++) {
        uint8_t sta[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0x00, static_cast<uint8_t>(i)};
        t.ingest(kAp, sta, kf, buf, n, 6, -50, 1);
    }
    TEST_ASSERT_EQUAL_UINT8(Table::kMaxTargets, t.count());
    TEST_ASSERT_EQUAL_UINT32(4, t.dropped());
}

void test_a_beacon_arriving_after_the_handshake_still_names_it() {
    // The common case in the field: the client joins, we hear the handshake,
    // and the next beacon is up to a tenth of a second behind it.
    Table& t = table();
    t.clear();
    feed(t, m2(1));
    TEST_ASSERT_FALSE(t.at(0).named());

    t.noteBeacon(kAp, "corp-wifi", 6, -44);
    TEST_ASSERT_TRUE(t.at(0).named());
    TEST_ASSERT_EQUAL_STRING("corp-wifi", t.at(0).ssid);
}

void test_a_beacon_arriving_first_names_the_handshake_immediately() {
    Table& t = table();
    t.clear();
    t.noteBeacon(kAp, "corp-wifi", 11, -44);
    feed(t, m2(1));   // heard on channel 6, five channels away
    TEST_ASSERT_EQUAL_STRING("corp-wifi", t.at(0).ssid);
    TEST_ASSERT_EQUAL_UINT8(11, t.at(0).channel);
    TEST_ASSERT_TRUE(t.at(0).channelFromBeacon);
}

void test_the_beacons_channel_outranks_the_one_we_heard_it_on() {
    // 2.4 GHz channels overlap. A strong AP on 11 is audible while the radio
    // sits on 6, and taking 6 as its channel sends the operator to lock onto
    // an empty channel and wait there.
    Table& t = table();
    t.clear();
    feed(t, m2(1));                        // heard on 6, no beacon yet
    TEST_ASSERT_EQUAL_UINT8(6, t.at(0).channel);
    TEST_ASSERT_FALSE(t.at(0).channelFromBeacon);

    t.noteBeacon(kAp, "corp-wifi", 11, -44);
    TEST_ASSERT_EQUAL_UINT8(11, t.at(0).channel);

    feed(t, m3(2));                        // another frame heard on 6
    TEST_ASSERT_EQUAL_UINT8(11, t.at(0).channel);
}

void test_quality_ranks_pmkid_below_a_handshake() {
    TEST_ASSERT_TRUE(Quality::Nothing < Quality::Fragment);
    TEST_ASSERT_TRUE(Quality::Fragment < Quality::Pmkid);
    TEST_ASSERT_TRUE(Quality::Pmkid < Quality::Handshake);
    TEST_ASSERT_TRUE(Quality::Handshake < Quality::Both);
}

// ---- export -----------------------------------------------------------------

namespace {

Target sampleTarget() {
    Target t;
    std::memcpy(t.bssid, kAp, 6);
    std::memcpy(t.sta, kSta, 6);
    std::snprintf(t.ssid, kSsidBuf, "%s", "ab");
    return t;
}

}  // namespace

void test_pmkid_line_matches_the_22000_format_exactly() {
    Target t = sampleTarget();
    std::memset(t.pmkid, 0xAB, kPmkidLen);
    t.havePmkid = true;

    char line[kHashLineMax];
    const size_t n = writePmkidLine(t, line, sizeof(line));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_STRING(
        "WPA*01*abababababababababababababababab*001122334455*aabbccddee01*6162***",
        line);
}

void test_eapol_line_matches_the_22000_format_exactly() {
    Target t = sampleTarget();
    t.haveM1 = true; t.haveM2 = true;
    t.rcM1 = 5; t.rcM2 = 5;
    t.haveAnonce = true; t.anonceFromM1 = true;
    std::memset(t.anonce, 0x11, kNonceLen);
    std::memset(t.mic, 0x22, kMicLen);
    t.eapol[0] = 0x02; t.eapol[1] = 0x03;
    t.eapolLen = 2;

    char line[kHashLineMax];
    const size_t n = writeEapolLine(t, line, sizeof(line));
    TEST_ASSERT_TRUE(n > 0);

    TEST_ASSERT_EQUAL_STRING(
        "WPA*02*22222222222222222222222222222222*001122334455*aabbccddee01*6162*"
        "1111111111111111111111111111111111111111111111111111111111111111*0203*00",
        line);
}

void test_the_essid_is_hex_encoded_so_a_hostile_name_cannot_break_the_line() {
    // SSIDs are 32 arbitrary octets chosen by whoever set the AP up. A star or
    // a newline in one would otherwise split a record in the output file.
    Target t = sampleTarget();
    std::snprintf(t.ssid, kSsidBuf, "%s", "a*b\nc");
    std::memset(t.pmkid, 0x01, kPmkidLen);
    t.havePmkid = true;

    char line[kHashLineMax];
    TEST_ASSERT_TRUE(writePmkidLine(t, line, sizeof(line)) > 0);
    TEST_ASSERT_NULL(std::strchr(line, '\n'));
    TEST_ASSERT_NOT_NULL(std::strstr(line, "*612a620a63*"));
}

void test_a_target_with_nothing_produces_no_line() {
    Target t = sampleTarget();
    char line[kHashLineMax];
    TEST_ASSERT_EQUAL_size_t(0, writePmkidLine(t, line, sizeof(line)));
    TEST_ASSERT_EQUAL_STRING("", line);
    TEST_ASSERT_EQUAL_size_t(0, writeEapolLine(t, line, sizeof(line)));
    TEST_ASSERT_EQUAL_STRING("", line);
}

void test_a_line_that_does_not_fit_is_not_written_at_all() {
    // Half a hash line in a file is worse than none: it silently corrupts the
    // record after it too.
    Target t = sampleTarget();
    std::memset(t.pmkid, 0xAB, kPmkidLen);
    t.havePmkid = true;

    char small[20];
    TEST_ASSERT_EQUAL_size_t(0, writePmkidLine(t, small, sizeof(small)));
    TEST_ASSERT_EQUAL_STRING("", small);
}

void test_the_longest_possible_line_fits_the_declared_buffer() {
    Target t;
    std::memcpy(t.bssid, kAp, 6);
    std::memcpy(t.sta, kSta, 6);
    std::memset(t.ssid, 'W', kSsidMax);
    t.ssid[kSsidMax] = '\0';
    t.haveM1 = true; t.haveM2 = true;
    t.haveAnonce = true; t.anonceFromM1 = true;
    std::memset(t.anonce, 0xFF, kNonceLen);
    std::memset(t.mic, 0xFF, kMicLen);
    std::memset(t.eapol, 0xFF, kEapolMax);
    t.eapolLen = kEapolMax;

    char line[kHashLineMax];
    TEST_ASSERT_TRUE(writeEapolLine(t, line, sizeof(line)) > 0);
}

void test_pcap_global_header_is_byte_exact() {
    uint8_t h[kPcapGlobalHeaderLen];
    TEST_ASSERT_EQUAL_size_t(kPcapGlobalHeaderLen,
                             writePcapGlobalHeader(h, sizeof(h), 2304));
    const uint8_t want[kPcapGlobalHeaderLen] = {
        0xD4, 0xC3, 0xB2, 0xA1,   // magic, little endian
        0x02, 0x00, 0x04, 0x00,   // version 2.4
        0x00, 0x00, 0x00, 0x00,   // thiszone
        0x00, 0x00, 0x00, 0x00,   // sigfigs
        0x00, 0x09, 0x00, 0x00,   // snaplen 2304
        0x69, 0x00, 0x00, 0x00,   // 105: IEEE 802.11
    };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, h, kPcapGlobalHeaderLen);
}

void test_pcap_record_header_never_claims_more_stored_than_captured() {
    // inclLen > origLen makes every reader treat the rest of the file as
    // corrupt, and the operator loses the whole capture, not one frame.
    uint8_t h[kPcapRecordHeaderLen];
    TEST_ASSERT_EQUAL_size_t(kPcapRecordHeaderLen,
                             writePcapRecordHeader(h, sizeof(h), 1, 2, 300, 100));
    TEST_ASSERT_EQUAL_UINT8(300 & 0xFF, h[8]);
    TEST_ASSERT_EQUAL_UINT8(300 & 0xFF, h[12]);
}

void test_pcap_headers_refuse_a_short_buffer() {
    uint8_t h[8];
    TEST_ASSERT_EQUAL_size_t(0, writePcapGlobalHeader(h, sizeof(h), 2304));
    TEST_ASSERT_EQUAL_size_t(0, writePcapRecordHeader(h, sizeof(h), 1, 2, 3, 4));
}

// -----------------------------------------------------------------------------

int main() {
    UNITY_BEGIN();

    RUN_TEST(test_plain_data_header_is_24_bytes);
    RUN_TEST(test_qos_data_header_carries_two_extra_bytes);
    RUN_TEST(test_four_address_frame_adds_addr4);
    RUN_TEST(test_ordered_qos_data_adds_ht_control);
    RUN_TEST(test_ordered_management_frame_does_not_add_ht_control);
    RUN_TEST(test_short_buffer_is_rejected_not_read_past);
    RUN_TEST(test_qos_frame_shorter_than_its_own_header_is_rejected);

    RUN_TEST(test_uplink_frame_puts_bssid_in_addr1);
    RUN_TEST(test_downlink_frame_puts_bssid_in_addr2);
    RUN_TEST(test_wds_frame_has_no_single_station);
    RUN_TEST(test_group_addresses_are_not_stations);

    RUN_TEST(test_beacon_yields_ssid_and_channel);
    RUN_TEST(test_nul_padded_ssid_counts_as_hidden);
    RUN_TEST(test_element_running_past_the_end_is_flagged_not_read);
    RUN_TEST(test_oversized_ssid_is_clamped_to_32_bytes);
    RUN_TEST(test_vendor_wpa_element_is_recognised);

    RUN_TEST(test_pmf_required_is_read_past_the_variable_length_suite_lists);
    RUN_TEST(test_a_network_with_no_pmf_bits_reports_neither);
    RUN_TEST(test_pmf_required_implies_capable);
    RUN_TEST(test_a_suite_count_running_past_the_end_reports_malformed_not_pmf);
    RUN_TEST(test_a_truncated_rsn_element_stops_cleanly);
    RUN_TEST(test_vendor_suites_are_skipped_not_misread);
    RUN_TEST(test_beacon_carries_the_rsn_details_through);
    RUN_TEST(test_wps_is_told_apart_from_the_old_wpa_element);

    RUN_TEST(test_eapol_payload_found_over_llc_snap);
    RUN_TEST(test_protected_frame_is_never_treated_as_eapol);
    RUN_TEST(test_non_eapol_ethertype_is_ignored);

    RUN_TEST(test_messages_are_classified_from_the_key_info_bits);
    RUN_TEST(test_m2_and_m4_are_told_apart_by_secure_and_key_data);
    RUN_TEST(test_group_key_handshake_is_not_mistaken_for_the_four_way);
    RUN_TEST(test_replay_counter_is_read_big_endian);
    RUN_TEST(test_disagreeing_length_fields_are_rejected);
    RUN_TEST(test_key_data_longer_than_the_buffer_is_rejected);
    RUN_TEST(test_truncated_and_non_key_payloads_are_rejected);

    RUN_TEST(test_pmkid_is_lifted_out_of_the_m1_key_data);
    RUN_TEST(test_all_zero_pmkid_is_reported_as_absent);
    RUN_TEST(test_pmkid_is_not_hunted_for_in_encrypted_key_data);
    RUN_TEST(test_pmkid_kde_running_past_the_key_data_is_rejected);
    RUN_TEST(test_other_kdes_are_skipped_to_reach_the_pmkid);
    RUN_TEST(test_pmkid_is_only_taken_from_m1);

    RUN_TEST(test_m1_and_m2_with_matching_counters_pair_cleanly);
    RUN_TEST(test_m2_and_m3_pair_when_the_counter_steps_up_by_one);
    RUN_TEST(test_mismatched_counters_still_export_but_are_flagged);
    RUN_TEST(test_m2_alone_is_not_a_handshake);
    RUN_TEST(test_m1_and_m3_without_m2_is_not_a_handshake);
    RUN_TEST(test_the_stored_eapol_blob_has_its_mic_zeroed);
    RUN_TEST(test_the_anonce_from_m3_is_used_when_m1_was_missed);
    RUN_TEST(test_targets_are_keyed_on_the_ap_and_station_pair);
    RUN_TEST(test_group_and_self_addressed_frames_are_refused);
    RUN_TEST(test_a_full_table_counts_what_it_drops);
    RUN_TEST(test_a_beacon_arriving_after_the_handshake_still_names_it);
    RUN_TEST(test_a_beacon_arriving_first_names_the_handshake_immediately);
    RUN_TEST(test_the_beacons_channel_outranks_the_one_we_heard_it_on);
    RUN_TEST(test_quality_ranks_pmkid_below_a_handshake);

    RUN_TEST(test_pmkid_line_matches_the_22000_format_exactly);
    RUN_TEST(test_eapol_line_matches_the_22000_format_exactly);
    RUN_TEST(test_the_essid_is_hex_encoded_so_a_hostile_name_cannot_break_the_line);
    RUN_TEST(test_a_target_with_nothing_produces_no_line);
    RUN_TEST(test_a_line_that_does_not_fit_is_not_written_at_all);
    RUN_TEST(test_the_longest_possible_line_fits_the_declared_buffer);
    RUN_TEST(test_pcap_global_header_is_byte_exact);
    RUN_TEST(test_pcap_record_header_never_claims_more_stored_than_captured);
    RUN_TEST(test_pcap_headers_refuse_a_short_buffer);

    return UNITY_END();
}
