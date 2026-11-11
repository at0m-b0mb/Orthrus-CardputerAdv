#include "dot11/inject.h"

#include <cstring>

namespace orthrus::dot11 {

namespace {

// Frame control, first byte: version 0, type and subtype.
//   management type = 0, so the byte is subtype << 4.
constexpr uint8_t fc0(uint8_t subtype) {
    return static_cast<uint8_t>(subtype << 4);
}

constexpr uint8_t kSubtypeDisassoc = 0x0A;

// Capability information, as a beacon carries it.
//   bit 0 ESS, bit 4 Privacy.
constexpr uint16_t kCapEss     = 0x0001;
constexpr uint16_t kCapPrivacy = 0x0010;

// The whole 802.11 management header, up to and including sequence control.
// Returns the bytes written, which is always 24.
size_t writeMgmtHeader(uint8_t* out, uint8_t subtype,
                       const uint8_t addr1[kMacLen],
                       const uint8_t addr2[kMacLen],
                       const uint8_t addr3[kMacLen], Sequencer& seq) {
    out[0] = fc0(subtype);
    out[1] = 0x00;   // no flags: not protected, not retried, no fragments
    out[2] = 0x00;   // duration, filled by the MAC
    out[3] = 0x00;
    std::memcpy(out + 4,  addr1, kMacLen);   // receiver
    std::memcpy(out + 10, addr2, kMacLen);   // transmitter
    std::memcpy(out + 16, addr3, kMacLen);   // BSSID

    // Sequence control: fragment number in the low 4 bits, sequence number in
    // the top 12. Little endian, like every multi-byte field in the header.
    const uint16_t sc = static_cast<uint16_t>(seq.next() << 4);
    out[22] = static_cast<uint8_t>(sc & 0xFF);
    out[23] = static_cast<uint8_t>(sc >> 8);
    return 24;
}

void putLe16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>(v >> 8);
}

// ---- information elements ---------------------------------------------------

// RSN element for WPA2-PSK with CCMP everywhere. 22 bytes including the id and
// length, and every four-byte group is an 00-0F-AC suite selector.
constexpr uint8_t kRsnWpa2Psk[] = {
    0x30, 0x14,              // element id 48, length 20
    0x01, 0x00,              // version 1
    0x00, 0x0F, 0xAC, 0x04,  // group cipher: CCMP-128
    0x01, 0x00,              // one pairwise cipher
    0x00, 0x0F, 0xAC, 0x04,  // pairwise: CCMP-128
    0x01, 0x00,              // one AKM
    0x00, 0x0F, 0xAC, 0x02,  // AKM: PSK
    0x00, 0x00,              // RSN capabilities: no PMF
};

// The same, with SAE as the AKM and both management-frame bits set:
// MFPC (bit 6) and MFPR (bit 7) give capabilities 0x00C0.
constexpr uint8_t kRsnWpa3Sae[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0F, 0xAC, 0x04,
    0x01, 0x00,
    0x00, 0x0F, 0xAC, 0x04,
    0x01, 0x00,
    0x00, 0x0F, 0xAC, 0x08,  // AKM: SAE
    0xC0, 0x00,              // MFPC | MFPR
};

// Supported rates: the four 802.11b rates with the basic-rate bit set, then
// four 802.11g rates. Enough that a client does not discard the beacon for
// advertising a rate set it cannot use.
constexpr uint8_t kRates[] = {
    0x01, 0x08,
    0x82, 0x84, 0x8B, 0x96,  // 1, 2, 5.5, 11 Mbps -- basic
    0x0C, 0x12, 0x18, 0x24,  // 6, 9, 12, 18 Mbps
};

size_t rsnFor(BeaconSecurity sec, const uint8_t** out) {
    switch (sec) {
        case BeaconSecurity::Wpa2Psk: *out = kRsnWpa2Psk; return sizeof(kRsnWpa2Psk);
        case BeaconSecurity::Wpa3Sae: *out = kRsnWpa3Sae; return sizeof(kRsnWpa3Sae);
        case BeaconSecurity::Open:    break;
    }
    *out = nullptr;
    return 0;
}

// SSID length, clamped to the 32 bytes the element can hold. A longer string is
// truncated rather than refused: the alternative is a surface that silently
// emits nothing because somebody typed a long name.
size_t ssidLen(const char* ssid) {
    if (ssid == nullptr) return 0;
    size_t n = std::strlen(ssid);
    return n > kSsidMax ? kSsidMax : n;
}

// Everything common to a beacon and a probe response: the fixed fields, then
// SSID, rates, DS parameter set, and the RSN element when there is one.
// `extra` is appended after the DS parameter set and before the RSN element,
// which is where a channel-switch element belongs.
size_t writeApBody(uint8_t* out, size_t cap, const char* ssid,
                   uint8_t channel, BeaconSecurity sec,
                   const uint8_t* extra, size_t extraLen) {
    const size_t sl = ssidLen(ssid);
    const uint8_t* rsn = nullptr;
    const size_t rsnLen = rsnFor(sec, &rsn);

    const size_t need = 12            // timestamp, interval, capability
                      + 2 + sl        // SSID element
                      + sizeof(kRates)
                      + 3             // DS parameter set
                      + extraLen
                      + rsnLen;
    if (cap < need) return 0;

    size_t i = 0;

    // Timestamp. Left at zero: it is the access point's own microsecond clock
    // and nothing receiving this frame can check it against anything.
    std::memset(out + i, 0, 8);
    i += 8;

    putLe16(out + i, 100);  // beacon interval, 100 TU -- about 102 ms
    i += 2;

    uint16_t capInfo = kCapEss;
    if (sec != BeaconSecurity::Open) capInfo |= kCapPrivacy;
    putLe16(out + i, capInfo);
    i += 2;

    out[i++] = 0x00;                        // SSID element
    out[i++] = static_cast<uint8_t>(sl);
    if (sl) std::memcpy(out + i, ssid, sl);
    i += sl;

    std::memcpy(out + i, kRates, sizeof(kRates));
    i += sizeof(kRates);

    out[i++] = 0x03;                        // DS parameter set
    out[i++] = 0x01;
    out[i++] = channel;

    if (extraLen) {
        std::memcpy(out + i, extra, extraLen);
        i += extraLen;
    }

    if (rsnLen) {
        std::memcpy(out + i, rsn, rsnLen);
        i += rsnLen;
    }

    return i;
}

size_t buildDisconnect(uint8_t* out, size_t cap, uint8_t subtype,
                       const uint8_t dest[kMacLen], const uint8_t src[kMacLen],
                       const uint8_t bssid[kMacLen], uint16_t reason,
                       Sequencer& seq) {
    if (out == nullptr || dest == nullptr || src == nullptr || bssid == nullptr)
        return 0;
    if (cap < 26) return 0;

    size_t i = writeMgmtHeader(out, subtype, dest, src, bssid, seq);
    putLe16(out + i, reason);
    i += 2;
    return i;
}

}  // namespace

size_t buildDeauth(uint8_t* out, size_t cap, const uint8_t dest[kMacLen],
                   const uint8_t src[kMacLen], const uint8_t bssid[kMacLen],
                   uint16_t reason, Sequencer& seq) {
    return buildDisconnect(out, cap, kSubtypeDeauth, dest, src, bssid, reason, seq);
}

size_t buildDisassoc(uint8_t* out, size_t cap, const uint8_t dest[kMacLen],
                     const uint8_t src[kMacLen], const uint8_t bssid[kMacLen],
                     uint16_t reason, Sequencer& seq) {
    return buildDisconnect(out, cap, kSubtypeDisassoc, dest, src, bssid, reason, seq);
}

size_t buildBeacon(uint8_t* out, size_t cap, const char* ssid,
                   const uint8_t bssid[kMacLen], uint8_t channel,
                   BeaconSecurity sec, Sequencer& seq) {
    if (out == nullptr || bssid == nullptr || cap < 24) return 0;

    static const uint8_t kBroadcast[kMacLen] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const size_t hdr = writeMgmtHeader(out, kSubtypeBeacon, kBroadcast, bssid,
                                       bssid, seq);
    const size_t body = writeApBody(out + hdr, cap - hdr, ssid, channel, sec,
                                    nullptr, 0);
    if (body == 0) return 0;
    return hdr + body;
}

size_t buildCsaBeacon(uint8_t* out, size_t cap, const char* ssid,
                      const uint8_t bssid[kMacLen], uint8_t channel,
                      uint8_t newChannel, uint8_t count, BeaconSecurity sec,
                      Sequencer& seq) {
    if (out == nullptr || bssid == nullptr || cap < 24) return 0;

    // Channel Switch Announcement: element 37, three bytes.
    //   mode 1  -> stop transmitting until the switch
    //   channel -> where everybody is being sent
    //   count   -> beacon intervals remaining, 0 meaning now
    const uint8_t csa[5] = {0x25, 0x03, 0x01, newChannel, count};

    static const uint8_t kBroadcast[kMacLen] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const size_t hdr = writeMgmtHeader(out, kSubtypeBeacon, kBroadcast, bssid,
                                       bssid, seq);
    const size_t body = writeApBody(out + hdr, cap - hdr, ssid, channel, sec,
                                    csa, sizeof(csa));
    if (body == 0) return 0;
    return hdr + body;
}

size_t buildProbeResponse(uint8_t* out, size_t cap, const char* ssid,
                          const uint8_t bssid[kMacLen],
                          const uint8_t dest[kMacLen], uint8_t channel,
                          BeaconSecurity sec, Sequencer& seq) {
    if (out == nullptr || bssid == nullptr || dest == nullptr || cap < 24)
        return 0;

    const size_t hdr = writeMgmtHeader(out, kSubtypeProbeResp, dest, bssid,
                                       bssid, seq);
    const size_t body = writeApBody(out + hdr, cap - hdr, ssid, channel, sec,
                                    nullptr, 0);
    if (body == 0) return 0;
    return hdr + body;
}

size_t buildAuthRequest(uint8_t* out, size_t cap, const uint8_t bssid[kMacLen],
                        const uint8_t src[kMacLen], Sequencer& seq) {
    if (out == nullptr || bssid == nullptr || src == nullptr) return 0;
    if (cap < 30) return 0;

    size_t i = writeMgmtHeader(out, kSubtypeAuth, bssid, src, bssid, seq);
    putLe16(out + i, 0x0000); i += 2;   // algorithm: open system
    putLe16(out + i, 0x0001); i += 2;   // transaction sequence 1
    putLe16(out + i, 0x0000); i += 2;   // status: successful
    return i;
}

size_t buildAssocRequest(uint8_t* out, size_t cap, const char* ssid,
                         const uint8_t bssid[kMacLen],
                         const uint8_t src[kMacLen], Sequencer& seq) {
    if (out == nullptr || bssid == nullptr || src == nullptr) return 0;

    const size_t sl = ssidLen(ssid);
    const size_t need = 24 + 4 + 2 + sl + sizeof(kRates) + sizeof(kRsnWpa2Psk);
    if (cap < need) return 0;

    size_t i = writeMgmtHeader(out, kSubtypeAssocReq, bssid, src, bssid, seq);

    // Capability: ESS and Privacy, because this request is for a WPA2 network.
    putLe16(out + i, static_cast<uint16_t>(kCapEss | kCapPrivacy));
    i += 2;
    putLe16(out + i, 10);  // listen interval, in beacon intervals
    i += 2;

    out[i++] = 0x00;
    out[i++] = static_cast<uint8_t>(sl);
    if (sl) std::memcpy(out + i, ssid, sl);
    i += sl;

    std::memcpy(out + i, kRates, sizeof(kRates));
    i += sizeof(kRates);

    // Asking for PSK with CCMP specifically. An access point will not
    // volunteer a PMKID in answer to a request whose AKM it does not support,
    // so this element is the difference between a solicitation and a refusal.
    std::memcpy(out + i, kRsnWpa2Psk, sizeof(kRsnWpa2Psk));
    i += sizeof(kRsnWpa2Psk);

    return i;
}

void inventedAddress(uint8_t out[kMacLen], uint32_t salt) {
    if (out == nullptr) return;

    // A small deterministic mix. Not a hash and nothing depends on it being
    // one: it only has to spread consecutive salts across the space so a swarm
    // does not look like a counter.
    uint32_t x = salt * 2654435761u + 0x9E3779B9u;
    x ^= x >> 15;
    x *= 0x85EBCA6Bu;
    x ^= x >> 13;

    out[0] = static_cast<uint8_t>((x >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((x >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((x >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(x & 0xFF);
    // Two more bytes from a second round, so the last octets vary too.
    uint32_t y = x * 0xC2B2AE35u + 0x27D4EB2Fu;
    y ^= y >> 16;
    out[4] = static_cast<uint8_t>((y >> 8) & 0xFF);
    out[5] = static_cast<uint8_t>(y & 0xFF);

    // Locally administered, individual. This is the part that matters: the
    // address is now one the registry never assigned, so nothing in the
    // resulting capture can be attributed to a real manufacturer.
    out[0] = static_cast<uint8_t>((out[0] | 0x02) & 0xFE);
}

bool addressIsInvented(const uint8_t addr[kMacLen]) {
    if (addr == nullptr) return false;
    return (addr[0] & 0x02) != 0 && (addr[0] & 0x01) == 0;
}

}  // namespace orthrus::dot11
