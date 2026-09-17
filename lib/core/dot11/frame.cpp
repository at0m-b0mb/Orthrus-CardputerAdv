#include "dot11/frame.h"

#include <cstring>

namespace orthrus::dot11 {

namespace {

constexpr size_t kBaseHeaderLen = 24;
constexpr size_t kAddr4Len      = 6;
constexpr size_t kQosCtrlLen    = 2;
constexpr size_t kHtCtrlLen     = 4;

// LLC/SNAP for EAPOL: AA AA 03 | 00 00 00 | 88 8E
constexpr uint8_t kSnapEapol[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};

// Beacon and probe response fixed parameters: timestamp(8), interval(2),
// capability(2). The tagged elements follow.
constexpr size_t kBeaconFixedLen = 12;

constexpr uint8_t kElemSsid   = 0x00;
constexpr uint8_t kElemDsSet  = 0x03;
constexpr uint8_t kElemRsn    = 0x30;
constexpr uint8_t kElemVendor = 0xDD;

// RSN capability bits, 802.11-2020 table 9-192.
constexpr uint16_t kRsnCapMfpr = 0x0040;  // management frame protection REQUIRED
constexpr uint16_t kRsnCapMfpc = 0x0080;  // management frame protection CAPABLE

uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

// Every suite selector is a 3 byte OUI plus a 1 byte type. 00-0F-AC is the
// IEEE's own; anything else is a vendor extension we do not claim to know.
bool isIeeeSuite(const uint8_t* p) {
    return p[0] == 0x00 && p[1] == 0x0F && p[2] == 0xAC;
}

constexpr char kHex[] = "0123456789abcdef";

}  // namespace

bool parseHeader(const uint8_t* frame, size_t len, FrameInfo& out) {
    if (frame == nullptr || len < kBaseHeaderLen) return false;

    const uint8_t fc0 = frame[0];
    const uint8_t fc1 = frame[1];

    out.type    = static_cast<FrameType>((fc0 >> 2) & 0x03);
    out.subtype = static_cast<uint8_t>((fc0 >> 4) & 0x0F);
    out.toDs    = (fc1 & 0x01) != 0;
    out.fromDs  = (fc1 & 0x02) != 0;
    out.protectedFrame = (fc1 & 0x40) != 0;
    out.ordered = (fc1 & 0x80) != 0;

    std::memcpy(out.addr1, frame + 4, kMacLen);
    std::memcpy(out.addr2, frame + 10, kMacLen);
    std::memcpy(out.addr3, frame + 16, kMacLen);

    size_t hdr = kBaseHeaderLen;
    if (out.toDs && out.fromDs) hdr += kAddr4Len;  // four-address format

    // Only DATA frames carry QoS control, and only the QoS subtypes of those.
    // Management frames set the same bit in fc1 to mean "strictly ordered",
    // which has nothing to do with HT control.
    bool isQosData = false;
    if (out.type == FrameType::Data && (out.subtype & kDataQosBit) != 0) {
        isQosData = true;
        hdr += kQosCtrlLen;
    }
    if (isQosData && out.ordered) hdr += kHtCtrlLen;

    if (len < hdr) return false;
    out.headerLen = static_cast<uint16_t>(hdr);
    return true;
}

bool resolveEndpoints(const FrameInfo& fi, uint8_t bssid[kMacLen],
                      uint8_t sta[kMacLen]) {
    if (fi.toDs && fi.fromDs) return false;  // WDS: two APs, no single station

    if (fi.toDs) {
        // Uplink: addr1 BSSID, addr2 source (the station).
        std::memcpy(bssid, fi.addr1, kMacLen);
        std::memcpy(sta, fi.addr2, kMacLen);
        return true;
    }
    if (fi.fromDs) {
        // Downlink: addr1 destination (the station), addr2 BSSID.
        std::memcpy(bssid, fi.addr2, kMacLen);
        std::memcpy(sta, fi.addr1, kMacLen);
        return true;
    }

    // Neither bit: management, or an ad-hoc data frame. addr3 is the BSSID and
    // addr1 is whoever the frame is aimed at -- broadcast for a beacon, which
    // the caller is expected to notice rather than treat as a station.
    std::memcpy(bssid, fi.addr3, kMacLen);
    std::memcpy(sta, fi.addr1, kMacLen);
    return true;
}

bool parseRsn(const uint8_t* data, size_t len, RsnInfo& out) {
    out = RsnInfo{};

    // Version (2) is the only mandatory field. Everything after it is optional
    // and, critically, POSITIONAL: the capability bits can only be located by
    // walking the two variable-length suite lists in front of them. A parser
    // that reads the capabilities from a fixed offset gets the right answer on
    // a typical access point and the wrong one on anything unusual -- and the
    // wrong answer here means telling an operator a network is protected when
    // it is not.
    if (data == nullptr || len < 2) return false;
    out.present = true;

    size_t i = 2;  // past the version

    if (i + 4 > len) return true;  // group cipher absent: legal, nothing more to read
    i += 4;

    if (i + 2 > len) return true;
    const uint16_t pairwiseCount = le16(data + i);
    i += 2;
    // A count that runs past the end is either a malformed beacon or one built
    // to confuse a parser. Either way the capabilities cannot be located, so
    // nothing after this point is reported.
    if (i + static_cast<size_t>(pairwiseCount) * 4 > len) {
        out.malformed = true;
        return true;
    }
    for (uint16_t k = 0; k < pairwiseCount; k++) {
        const uint8_t* s = data + i + k * 4;
        if (!isIeeeSuite(s)) continue;
        switch (s[3]) {
            case 2: out.cipherTkip = true; break;
            case 4: out.cipherCcmp = true; break;
            case 8:
            case 9: out.cipherGcmp = true; break;
            default: break;
        }
    }
    i += static_cast<size_t>(pairwiseCount) * 4;

    if (i + 2 > len) return true;
    const uint16_t akmCount = le16(data + i);
    i += 2;
    if (i + static_cast<size_t>(akmCount) * 4 > len) {
        out.malformed = true;
        return true;
    }
    for (uint16_t k = 0; k < akmCount; k++) {
        const uint8_t* s = data + i + k * 4;
        if (!isIeeeSuite(s)) continue;
        switch (s[3]) {
            case 1:
            case 3:
            case 5:  out.akmEnterprise = true; break;
            case 2:  out.akmPsk        = true; break;
            case 6:  out.akmPskSha256  = true; break;
            case 8:  out.akmSae        = true; break;
            case 9:  out.akmFtSae      = true; break;
            case 18: out.akmOwe        = true; break;
            default: break;
        }
    }
    i += static_cast<size_t>(akmCount) * 4;

    // And finally the capabilities, which is what we came for.
    if (i + 2 > len) return true;
    const uint16_t caps = le16(data + i);
    out.pmfRequired = (caps & kRsnCapMfpr) != 0;
    out.pmfCapable  = (caps & kRsnCapMfpc) != 0;

    // Required implies capable. Some access points set only the required bit;
    // reporting such a network as "not capable" would be absurd.
    if (out.pmfRequired) out.pmfCapable = true;
    return true;
}

bool parseBeacon(const uint8_t* body, size_t len, BeaconInfo& out) {
    out = BeaconInfo{};
    if (body == nullptr || len < kBeaconFixedLen) return false;

    size_t i = kBeaconFixedLen;
    while (i + 2 <= len) {
        const uint8_t id  = body[i];
        const uint8_t elen = body[i + 1];
        const size_t  data = i + 2;

        // A length field that runs off the end is not a parse we can trust.
        // Take what we have and say the frame was truncated rather than
        // reading past the buffer.
        if (data + elen > len) {
            out.truncated = true;
            break;
        }

        switch (id) {
            case kElemSsid: {
                out.ssidPresent = true;
                const size_t n = elen > kSsidMax ? kSsidMax : elen;
                std::memcpy(out.ssid, body + data, n);
                out.ssid[n] = '\0';

                // A hidden network broadcasts either a zero-length SSID or one
                // padded with NULs. Both mean the same thing and neither is a
                // security control: the clients then shout the name instead.
                out.ssidHidden = true;
                for (size_t k = 0; k < n; k++) {
                    if (out.ssid[k] != '\0') { out.ssidHidden = false; break; }
                }
                if (out.ssidHidden) out.ssid[0] = '\0';
                break;
            }
            case kElemDsSet:
                if (elen >= 1) out.channel = body[data];
                break;
            case kElemRsn:
                out.hasRsn = true;
                parseRsn(body + data, elen, out.rsn);
                break;
            case kElemVendor:
                // Microsoft OUI 00-50-F2. Type 1 is the pre-RSN WPA element;
                // type 4 is Wi-Fi Protected Setup, which is worth reporting in
                // its own right -- WPS is how a network with a long passphrase
                // gets opened anyway.
                if (elen >= 4 && body[data] == 0x00 && body[data + 1] == 0x50 &&
                    body[data + 2] == 0xF2) {
                    if (body[data + 3] == 0x01) out.hasWpa = true;
                    if (body[data + 3] == 0x04) out.hasWps = true;
                }
                break;
            default:
                break;
        }

        i = data + elen;
    }

    return true;
}

bool eapolPayload(const uint8_t* frame, size_t len, const FrameInfo& fi,
                  const uint8_t** payload, size_t* payloadLen) {
    if (payload == nullptr || payloadLen == nullptr) return false;
    *payload    = nullptr;
    *payloadLen = 0;

    if (fi.type != FrameType::Data) return false;

    // Null-data frames (subtype bit 2) carry no body at all.
    if ((fi.subtype & 0x04) != 0) return false;

    // Encrypted frames hold ciphertext. The EAPOL handshake runs before the
    // pairwise key is installed, so a real one is never protected; treating a
    // protected frame as EAPOL would parse random bytes as key material.
    if (fi.protectedFrame) return false;

    const size_t off = fi.headerLen;
    if (off + sizeof(kSnapEapol) > len) return false;
    if (std::memcmp(frame + off, kSnapEapol, sizeof(kSnapEapol)) != 0) return false;

    *payload    = frame + off + sizeof(kSnapEapol);
    *payloadLen = len - off - sizeof(kSnapEapol);
    return true;
}

void formatMacBare(const uint8_t mac[kMacLen], char out[13]) {
    for (size_t i = 0; i < kMacLen; i++) {
        out[i * 2]     = kHex[(mac[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[mac[i] & 0x0F];
    }
    out[12] = '\0';
}

void formatMacColons(const uint8_t mac[kMacLen], char out[18]) {
    size_t p = 0;
    for (size_t i = 0; i < kMacLen; i++) {
        if (i) out[p++] = ':';
        out[p++] = kHex[(mac[i] >> 4) & 0x0F];
        out[p++] = kHex[mac[i] & 0x0F];
    }
    out[p] = '\0';
}

bool macEqual(const uint8_t a[kMacLen], const uint8_t b[kMacLen]) {
    return std::memcmp(a, b, kMacLen) == 0;
}

bool macIsZero(const uint8_t a[kMacLen]) {
    for (size_t i = 0; i < kMacLen; i++)
        if (a[i]) return false;
    return true;
}

bool macIsGroup(const uint8_t a[kMacLen]) {
    // Bit 0 of the first octet is the individual/group bit. Broadcast and every
    // multicast address has it set; the all-zero address is not a station
    // either, and clears the bit, so it is checked separately.
    return (a[0] & 0x01) != 0 || macIsZero(a);
}

}  // namespace orthrus::dot11
