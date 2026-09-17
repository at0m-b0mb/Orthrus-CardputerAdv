#include "dot11/eapol.h"

#include <cstring>

namespace orthrus::dot11 {

namespace {

// Offsets inside the 802.1X payload.
constexpr size_t kOffVersion    = 0;
constexpr size_t kOffType       = 1;
constexpr size_t kOffLength     = 2;   // 2 bytes, big endian
constexpr size_t kOffDescriptor = 4;
constexpr size_t kOffKeyInfo    = 5;   // 2 bytes, big endian
constexpr size_t kOffReplay     = 9;   // 8 bytes, big endian
constexpr size_t kOffNonce      = 17;  // 32 bytes
constexpr size_t kOffKeyDataLen = 97;  // 2 bytes, big endian
constexpr size_t kOffKeyData    = 99;

uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint64_t be64(const uint8_t* p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

}  // namespace

bool parseKeyFrame(const uint8_t* payload, size_t len, KeyFrame& out) {
    out = KeyFrame{};
    if (payload == nullptr || len < kEapolKeyMinLen) return false;

    // EAPOL version is 1, 2 or 3 in the wild. It is not worth rejecting on,
    // but type must be EAPOL-Key: anything else is EAP or a start/logoff.
    if (payload[kOffType] != kEapolTypeKey) return false;
    (void)payload[kOffVersion];

    const uint8_t descriptor = payload[kOffDescriptor];
    if (descriptor != kDescriptorRsn && descriptor != kDescriptorWpa) return false;

    const uint16_t keyInfo    = be16(payload + kOffKeyInfo);
    const uint16_t keyDataLen = be16(payload + kOffKeyDataLen);

    // Two independent length claims: the 802.1X header's own, and the key data
    // length. They have to agree with each other AND fit inside the buffer, or
    // this is not a frame we can reason about.
    const uint16_t bodyLen = be16(payload + kOffLength);
    const size_t   implied = kOffKeyData + keyDataLen;
    if (implied > len) return false;
    if (bodyLen != 0 && static_cast<size_t>(bodyLen) + kEapolHeaderLen != implied)
        return false;

    out.descriptorType = descriptor;
    out.keyInfo        = keyInfo;
    out.keyVersion     = static_cast<uint8_t>(keyInfo & kKeyInfoVersionMask);
    out.replayCounter  = be64(payload + kOffReplay);
    out.keyDataLen     = keyDataLen;
    out.keyData        = keyDataLen ? (payload + kOffKeyData) : nullptr;
    out.payloadLen     = static_cast<uint16_t>(implied);

    std::memcpy(out.nonce, payload + kOffNonce, kNonceLen);
    out.nonceIsZero = true;
    for (size_t i = 0; i < kNonceLen; i++) {
        if (out.nonce[i]) { out.nonceIsZero = false; break; }
    }

    out.micPresent = (keyInfo & kKeyInfoMic) != 0;
    if (out.micPresent) std::memcpy(out.mic, payload + kMicOffset, kMicLen);

    // Only the pairwise handshake is of interest. The group key handshake uses
    // the same frame shape and would otherwise be mistaken for M3/M4.
    if ((keyInfo & kKeyInfoPairwise) == 0) {
        out.message = Message::Unknown;
        return true;
    }
    // A Request frame is the client asking for a rekey, not part of the
    // four-way exchange, and its counters do not belong in a pairing.
    if ((keyInfo & kKeyInfoRequest) != 0) {
        out.message = Message::Unknown;
        return true;
    }

    const bool ack    = (keyInfo & kKeyInfoAck) != 0;
    const bool mic    = out.micPresent;
    const bool secure = (keyInfo & kKeyInfoSecure) != 0;

    if (ack && !mic) {
        out.message = Message::M1;
    } else if (ack && mic) {
        out.message = Message::M3;
    } else if (!ack && mic) {
        // M2 and M4 are the same shape apart from two tells. Under RSN the
        // Secure bit is what separates them; under the original WPA it may be
        // clear in both, and there the discriminator is that M2 carries the
        // client's RSN/WPA element while M4 carries nothing.
        //
        // Both tells are checked because relying on either alone mislabels a
        // real capture -- and a mislabelled M4 stored as M2 produces a hash
        // line with the wrong EAPOL bytes, which simply never cracks.
        out.message = (!secure && keyDataLen > 0) ? Message::M2 : Message::M4;
    } else {
        out.message = Message::Unknown;
    }

    return true;
}

bool extractPmkid(const KeyFrame& kf, uint8_t out[kPmkidLen]) {
    if (out == nullptr) return false;
    std::memset(out, 0, kPmkidLen);

    if (kf.message != Message::M1) return false;
    if (kf.keyData == nullptr || kf.keyDataLen == 0) return false;

    // Encrypted key data is ciphertext under a key we do not have. Scanning it
    // for a KDE pattern would occasionally "find" one made of noise.
    if (kf.encrypted()) return false;

    // Walk the key data as information elements looking for the RSN PMKID KDE:
    //   DD <len> 00 0F AC 04 <16 bytes>
    size_t i = 0;
    while (i + 2 <= kf.keyDataLen) {
        const uint8_t id   = kf.keyData[i];
        const uint8_t elen = kf.keyData[i + 1];
        const size_t  data = i + 2;
        if (data + elen > kf.keyDataLen) return false;  // truncated: trust none of it

        if (id == 0xDD && elen >= 4 + kPmkidLen &&
            kf.keyData[data]     == 0x00 &&
            kf.keyData[data + 1] == 0x0F &&
            kf.keyData[data + 2] == 0xAC &&
            kf.keyData[data + 3] == 0x04) {
            const uint8_t* p = kf.keyData + data + 4;

            // Some access points emit a zero-filled PMKID KDE as a placeholder.
            // It is not a credential and a cracker run against it is wasted, so
            // it is reported as absent rather than as a find.
            bool allZero = true;
            for (size_t k = 0; k < kPmkidLen; k++) {
                if (p[k]) { allZero = false; break; }
            }
            if (allZero) return false;

            std::memcpy(out, p, kPmkidLen);
            return true;
        }

        // A zero-length padding element at the end is normal; anything else
        // with a zero length would loop forever.
        if (elen == 0 && id == 0x00) break;
        i = data + elen;
    }
    return false;
}

const char* messageName(Message m) {
    switch (m) {
        case Message::M1: return "M1";
        case Message::M2: return "M2";
        case Message::M3: return "M3";
        case Message::M4: return "M4";
        default:          return "--";
    }
}

}  // namespace orthrus::dot11
