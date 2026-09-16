#include "grade.h"

namespace orthrus::credential {
namespace {

uint8_t severityWeight(Severity s) {
    switch (s) {
        case Severity::Critical: return 50;
        case Severity::High:     return 30;
        case Severity::Medium:   return 15;
        case Severity::Low:      return 6;
        case Severity::Info:     return 0;
    }
    return 0;
}

uint8_t clampConfidence(uint8_t c) {
    return c > kConfidenceCeiling ? kConfidenceCeiling : c;
}

// Ceilings are applied as a curve rather than a clip, so ordering survives
// underneath them: of two Crypto1 cards, the one that also answered a default
// key still ranks worse. Clipping would flatten them to the same number.
uint8_t applyCeiling(uint8_t score, uint8_t ceiling) {
    return static_cast<uint8_t>((static_cast<uint32_t>(ceiling) * score) / 100u);
}

}  // namespace

bool FindingSet::add(FindingId id, Severity sev, uint8_t confidence) {
    if (count >= kMax) return false;
    if (confidence == 0) return false;
    items[count++] = Finding{id, sev, clampConfidence(confidence)};
    return true;
}

bool FindingSet::has(FindingId id) const {
    for (uint8_t i = 0; i < count; i++)
        if (items[i].id == id) return true;
    return false;
}

const Finding* FindingSet::get(FindingId id) const {
    for (uint8_t i = 0; i < count; i++)
        if (items[i].id == id) return &items[i];
    return nullptr;
}

Grade scoreToGrade(uint8_t score) {
    if (score >= 95) return Grade::APlus;
    if (score >= 85) return Grade::A;
    if (score >= 70) return Grade::B;
    if (score >= 55) return Grade::C;
    if (score >= 40) return Grade::D;
    return Grade::F;
}

const char* gradeName(Grade g) {
    switch (g) {
        case Grade::APlus: return "A+";
        case Grade::A:     return "A";
        case Grade::B:     return "B";
        case Grade::C:     return "C";
        case Grade::D:     return "D";
        case Grade::F:     return "F";
    }
    return "?";
}

const char* severityName(Severity s) {
    switch (s) {
        case Severity::Info:     return "INFO";
        case Severity::Low:      return "LOW";
        case Severity::Medium:   return "MEDIUM";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "?";
}

const char* findingTitle(FindingId id) {
    switch (id) {
        case FindingId::DefaultKeyAccepted:     return "Opened with a published key";
        case FindingId::ReadableWithoutAuth:    return "Readable with no key";
        case FindingId::NoCryptography:         return "No cryptography";
        case FindingId::BrokenCipher:           return "Broken cipher (Crypto1)";
        case FindingId::ClassicSectorsPresent:  return "Carries Crypto1 sectors";
        case FindingId::WeakCipher:             return "Weak cipher (3DES)";
        case FindingId::PasswordOnlyProtection: return "Password, not a cipher";
        case FindingId::ClonableUid:            return "4-byte UID";
        case FindingId::ReaderPolicyUnknown:    return "Reader policy not visible";
        case FindingId::DeeperProbeNotRun:      return "No key probe attempted";
    }
    return "?";
}

const char* findingDetail(FindingId id) {
    switch (id) {
        case FindingId::DefaultKeyAccepted:
            return "A sector opened with a key printed in every tutorial on the "
                   "subject. The contents can be read and rewritten at will.";
        case FindingId::ReadableWithoutAuth:
            return "User memory came out with no key at all. Whatever is stored "
                   "there is readable by anyone who walks past.";
        case FindingId::NoCryptography:
            return "There is nothing to authenticate against. The card can be "
                   "copied byte for byte onto a blank in seconds.";
        case FindingId::BrokenCipher:
            return "Crypto1 has been broken in public since 2008. Keys are "
                   "recovered in minutes with commodity hardware.";
        case FindingId::ClassicSectorsPresent:
            return "The card also exposes Crypto1 sectors. An attacker takes "
                   "the weaker half and ignores the stronger one.";
        case FindingId::WeakCipher:
            return "3DES is aging and its key sizes are short. Sound today, but "
                   "not what a new deployment should be choosing.";
        case FindingId::PasswordOnlyProtection:
            return "A 32-bit shared password is not encryption. It is sent on "
                   "request and can be brute forced.";
        case FindingId::ClonableUid:
            return "A 4-byte UID is not globally unique, and blank cards that "
                   "accept any UID cost very little.";
        case FindingId::ReaderPolicyUnknown:
            return "Most installations compare only the UID, which every card "
                   "broadcasts unauthenticated. That control is invisible from "
                   "here, so no card can be graded A+ on a read alone.";
        case FindingId::DeeperProbeNotRun:
            return "Only anticollision was performed. No keys were tried, so "
                   "nothing here rules out a default key.";
    }
    return "";
}

Assessment assess(const TagIdentity& tag) {
    Assessment out;
    FindingSet& fs = out.findings;

    const Family fam = tag.family();
    const Cipher cip = cipherFor(fam);
    const UidKind uid = tag.uidKind();

    // ---- proven by probing --------------------------------------------------
    // These are the strongest statements the tool can make, because we did the
    // thing rather than inferred it.

    if (tag.triedDefaultKeys && tag.defaultKeyAccepted) {
        fs.add(FindingId::DefaultKeyAccepted, Severity::Critical, 97);
    }

    if (tag.triedReadWithoutAuth && tag.readableWithoutAuth &&
        cip != Cipher::None) {
        // For a card with no cipher this is not a finding, it is the design;
        // NoCryptography already covers it and saying both is double counting.
        fs.add(FindingId::ReadableWithoutAuth, Severity::High, 95);
    }

    // ---- inherent to the card ----------------------------------------------

    switch (cip) {
        case Cipher::None:
            fs.add(FindingId::NoCryptography, Severity::Critical, 95);
            break;
        case Cipher::Crypto1:
            fs.add(FindingId::BrokenCipher, Severity::Critical, 97);
            break;
        case Cipher::Password:
            // Only a finding once we know a password is actually set; an NTAG
            // with no password configured is simply NoCryptography.
            if (tag.triedPasswordProbe && tag.passwordProtected) {
                fs.add(FindingId::PasswordOnlyProtection, Severity::Medium, 90);
            } else if (tag.triedPasswordProbe) {
                fs.add(FindingId::NoCryptography, Severity::Critical, 95);
            } else {
                fs.add(FindingId::PasswordOnlyProtection, Severity::Medium, 60);
            }
            break;
        case Cipher::Des3:
            fs.add(FindingId::WeakCipher, Severity::Medium, 85);
            break;
        case Cipher::Aes:
        case Cipher::Unknown:
            break;
    }

    // A card that is both ISO-DEP and Crypto1-compatible is carrying its own
    // weakest link around with it.
    if (tag.isClassicCompatible() && tag.isIso14443_4()) {
        fs.add(FindingId::ClassicSectorsPresent, Severity::High, 92);
    }

    if (uid == UidKind::Single4Byte) {
        fs.add(FindingId::ClonableUid, Severity::Medium, 90);
    }

    // ---- what we could not see ---------------------------------------------

    // Always present. It is the honest answer to "is this badge safe?", and it
    // costs nothing because Info findings carry no weight.
    fs.add(FindingId::ReaderPolicyUnknown, Severity::Info, 100);

    const bool probed = tag.triedDefaultKeys || tag.triedReadWithoutAuth ||
                        tag.triedPasswordProbe;
    if (!probed) {
        fs.add(FindingId::DeeperProbeNotRun, Severity::Info, 100);
        out.surfaceOnly = true;
    }

    // ---- score --------------------------------------------------------------

    int32_t score = 100;
    for (uint8_t i = 0; i < fs.count; i++) {
        const Finding& f = fs.items[i];
        score -= (static_cast<int32_t>(severityWeight(f.sev)) * f.confidence) / 100;
    }
    if (score < 0) score = 0;
    uint8_t s = static_cast<uint8_t>(score);

    // Ceilings, worst last so the strongest constraint wins.
    s = applyCeiling(s, kReadAloneCeiling);
    if (fs.has(FindingId::BrokenCipher) || fs.has(FindingId::ClassicSectorsPresent))
        s = applyCeiling(s, kBrokenCipherCeiling);
    if (fs.has(FindingId::NoCryptography))
        s = applyCeiling(s, kNoCryptoCeiling);
    if (fs.has(FindingId::DefaultKeyAccepted))
        s = applyCeiling(s, kDefaultKeyCeiling);

    out.score = s;
    out.grade = scoreToGrade(s);
    return out;
}

}  // namespace orthrus::credential
