// What a 13.56 MHz credential tells you before you authenticate to it.
//
// Everything in this header comes out of the anticollision exchange, which any
// reader in range can perform without keys, without permission, and without the
// cardholder noticing. That is the point: it is the attacker's view of the
// badge in someone's pocket.
//
// Pure and host-testable. No Arduino, no I2C, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::credential {

// The families worth telling apart, because they differ in how hard the
// credential is to copy -- which is the only question that matters.
enum class Family : uint8_t {
    Unknown = 0,

    // ISO14443-A, no cryptography at all
    MifareUltralight,     // no auth whatsoever
    NtagSeries,           // optional 32-bit password, not a cipher
    MifareUltralightC,    // 3DES

    // ISO14443-A with Crypto1: broken in public since 2008
    MifareClassic1K,
    MifareClassic4K,
    MifareClassicMini,
    MifarePlusSL1,        // Classic-compatible mode, so Crypto1 applies

    // ISO14443-4 with real ciphers
    MifareDesfire,        // DES/3DES/AES depending on generation
    MifarePlusSL3,        // AES
    JavaCardOrSmartMX,    // depends entirely on the applet

    // Other radio layers
    Iso14443B,
    Felica,
    Iso15693,
};

enum class UidKind : uint8_t {
    Unknown = 0,
    Single4Byte,   // not globally unique, and cheap to forge
    Double7Byte,   // manufacturer-assigned, globally unique
    Triple10Byte,
    RandomPerSession,  // 4-byte beginning 0x08: deliberately not an identifier
};

inline constexpr size_t kMaxUidLen = 10;
inline constexpr size_t kMaxAtsLen = 32;

// Exactly what a reader learns from anticollision, plus whatever an optional
// deeper probe managed to establish.
struct TagIdentity {
    uint16_t atqa = 0;            // as transmitted, low byte first on the wire
    uint8_t  sak  = 0;

    uint8_t  uid[kMaxUidLen] = {0};
    uint8_t  uidLen = 0;

    uint8_t  ats[kMaxAtsLen] = {0};
    uint8_t  atsLen = 0;

    // --- optional, filled only when the operator ran a deeper probe ---------
    // Each of these is a fact we either established or did not. "Not
    // established" must never be scored as "absent".
    bool triedDefaultKeys      = false;
    bool defaultKeyAccepted    = false;  // a sector opened with a published key
    uint8_t defaultKeySector   = 0;

    bool triedPasswordProbe    = false;
    bool passwordProtected     = false;  // NTAG PWD/AUTH0 actually configured

    bool readableWithoutAuth   = false;  // user memory dumped with no key
    bool triedReadWithoutAuth  = false;

    Family  family() const;
    UidKind uidKind() const;

    bool isIso14443_4() const { return (sak & 0x20) != 0; }
    bool isClassicCompatible() const { return (sak & 0x08) != 0; }
};

// Family identification from ATQA/SAK/ATS.
//
// The SAK bits are the load-bearing part: bit 3 (0x08) means Crypto1-compatible
// and bit 5 (0x20) means the card speaks ISO14443-4. A card can set both, which
// is what SmartMX and Mifare Plus SL1 do, and that combination is exactly the
// case a naive lookup table gets wrong.
Family identify(uint16_t atqa, uint8_t sak, const uint8_t* ats, uint8_t atsLen);

UidKind uidKindFor(uint8_t uidLen, const uint8_t* uid);

const char* familyName(Family f);
const char* uidKindName(UidKind k);

// The cipher a family relies on, which is most of the grade.
enum class Cipher : uint8_t {
    None = 0,      // nothing at all
    Password,      // a shared 32-bit value, not a cipher
    Crypto1,       // publicly broken
    Des3,          // weak by modern standards
    Aes,           // sound
    Unknown,       // depends on an applet we cannot see
};

Cipher cipherFor(Family f);
const char* cipherName(Cipher c);

}  // namespace orthrus::credential
