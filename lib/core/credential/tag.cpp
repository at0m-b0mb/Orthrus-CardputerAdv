#include "tag.h"

namespace orthrus::credential {

namespace {

// SAK bits that actually decide behaviour (NXP AN10833, ISO/IEC 14443-3).
constexpr uint8_t kSakIso14443_4   = 0x20;  // card speaks ISO-DEP
constexpr uint8_t kSakClassicCompat = 0x08; // Crypto1 sectors present

}  // namespace

UidKind uidKindFor(uint8_t uidLen, const uint8_t* uid) {
    switch (uidLen) {
        case 4:
            // A 4-byte UID beginning 0x08 is declared random-per-session by
            // ISO14443-3. That is a privacy feature, not a weakness, and
            // scoring it as a weak identifier would punish the right choice.
            if (uid != nullptr && uid[0] == 0x08) return UidKind::RandomPerSession;
            return UidKind::Single4Byte;
        case 7:  return UidKind::Double7Byte;
        case 10: return UidKind::Triple10Byte;
        default: return UidKind::Unknown;
    }
}

UidKind TagIdentity::uidKind() const { return uidKindFor(uidLen, uid); }

Family identify(uint16_t atqa, uint8_t sak, const uint8_t* ats, uint8_t atsLen) {
    const bool iso4    = (sak & kSakIso14443_4) != 0;
    const bool classic = (sak & kSakClassicCompat) != 0;

    // Order matters. A card that is BOTH Crypto1-compatible and ISO14443-4 is
    // a SmartMX or a Mifare Plus in SL1 -- and the honest answer is the weaker
    // half, because the Crypto1 sectors are still there to be attacked.
    if (classic && iso4) {
        return Family::MifarePlusSL1;
    }

    if (classic) {
        switch (sak) {
            case 0x09: return Family::MifareClassicMini;
            case 0x08: return Family::MifareClassic1K;
            case 0x18: return Family::MifareClassic4K;
            case 0x88: return Family::MifareClassic1K;  // Infineon-made 1K
            case 0x38: return Family::MifareClassic4K;  // SmartMX emulating 4K
            case 0x10: return Family::MifarePlusSL1;    // 2K SL2
            case 0x11: return Family::MifarePlusSL1;    // 4K SL2
            default:   return Family::MifareClassic1K;
        }
    }

    if (iso4) {
        // DESFire announces itself in the ATS historical bytes. The signature
        // is 75 77 81 02, which is what an EV1/EV2 actually answers with
        // (full ATS: 06 75 77 81 02 80). Without an ATS we can only say "some
        // ISO-DEP card", and we say that rather than guess.
        //
        // The bound is i + 3 < atsLen because the pattern is four bytes long
        // and must be allowed to sit at the very end of the ATS -- an earlier
        // version stopped one pair short and missed it there.
        static const uint8_t kDesfireHistorical[] = {0x75, 0x77, 0x81, 0x02};
        if (ats != nullptr && atsLen >= 4) {
            for (uint8_t i = 0; i + 3 < atsLen; i++) {
                if (ats[i] == kDesfireHistorical[0] &&
                    ats[i + 1] == kDesfireHistorical[1] &&
                    ats[i + 2] == kDesfireHistorical[2] &&
                    ats[i + 3] == kDesfireHistorical[3]) {
                    return Family::MifareDesfire;
                }
            }
        }
        // ATQA 0x0344 is the DESFire answer to request. Weaker evidence than
        // the ATS, so it is only consulted once that has not matched.
        if ((atqa & 0x00FF) == 0x0044) return Family::MifareDesfire;
        return Family::JavaCardOrSmartMX;
    }

    // SAK 0x00: no Crypto1, no ISO-DEP. Ultralight family or NTAG.
    if (sak == 0x00) {
        // ATQA 0x0044 is the whole Ultralight/NTAG line. The two cannot be told
        // apart from anticollision alone -- it needs a GET_VERSION -- so the
        // shared, weaker answer is the honest one until something probes deeper.
        if ((atqa & 0x00FF) == 0x0044) return Family::MifareUltralight;
        return Family::MifareUltralight;
    }

    return Family::Unknown;
}

Family TagIdentity::family() const { return identify(atqa, sak, ats, atsLen); }

const char* familyName(Family f) {
    switch (f) {
        case Family::Unknown:            return "unknown";
        case Family::MifareUltralight:   return "Mifare Ultralight";
        case Family::NtagSeries:         return "NTAG";
        case Family::MifareUltralightC:  return "Ultralight C";
        case Family::MifareClassic1K:    return "Mifare Classic 1K";
        case Family::MifareClassic4K:    return "Mifare Classic 4K";
        case Family::MifareClassicMini:  return "Mifare Mini";
        case Family::MifarePlusSL1:      return "Mifare Plus SL1";
        case Family::MifareDesfire:      return "DESFire";
        case Family::MifarePlusSL3:      return "Mifare Plus SL3";
        case Family::JavaCardOrSmartMX:  return "ISO-DEP card";
        case Family::Iso14443B:          return "ISO14443-B";
        case Family::Felica:             return "FeliCa";
        case Family::Iso15693:           return "ISO15693";
    }
    return "?";
}

const char* uidKindName(UidKind k) {
    switch (k) {
        case UidKind::Unknown:          return "unknown";
        case UidKind::Single4Byte:      return "4-byte";
        case UidKind::Double7Byte:      return "7-byte";
        case UidKind::Triple10Byte:     return "10-byte";
        case UidKind::RandomPerSession: return "random per session";
    }
    return "?";
}

Cipher cipherFor(Family f) {
    switch (f) {
        case Family::MifareUltralight:  return Cipher::None;
        case Family::NtagSeries:        return Cipher::Password;
        case Family::MifareUltralightC: return Cipher::Des3;

        case Family::MifareClassic1K:
        case Family::MifareClassic4K:
        case Family::MifareClassicMini:
        case Family::MifarePlusSL1:     return Cipher::Crypto1;

        case Family::MifareDesfire:
        case Family::MifarePlusSL3:     return Cipher::Aes;

        case Family::JavaCardOrSmartMX:
        case Family::Iso14443B:
        case Family::Felica:
        case Family::Iso15693:
        case Family::Unknown:           return Cipher::Unknown;
    }
    return Cipher::Unknown;
}

const char* cipherName(Cipher c) {
    switch (c) {
        case Cipher::None:     return "none";
        case Cipher::Password: return "password";
        case Cipher::Crypto1:  return "Crypto1 (broken)";
        case Cipher::Des3:     return "3DES";
        case Cipher::Aes:      return "AES";
        case Cipher::Unknown:  return "unknown";
    }
    return "?";
}

}  // namespace orthrus::credential
