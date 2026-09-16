// Grading a 13.56 MHz credential by how hard it is to copy.
//
// THE CEILING THAT SHAPES EVERYTHING HERE
//
// You can read a badge. You cannot see what the READER does with it, and that
// is where almost every real-world failure lives: the overwhelming majority of
// access control installations compare the UID and nothing else. A UID is
// transmitted unauthenticated to anyone in range, on every card ever made,
// including a DESFire with perfect AES. Against a UID-only reader, the finest
// credential on the market is a four-byte number that anyone can copy.
//
// So no card can earn A+ from a read alone. Not one. The grade describes the
// credential's potential, and the device says out loud that the control which
// actually matters is invisible from here. Anything else would be selling
// confidence we have no way to earn -- the same line this project holds in
// Airspace.
//
// Pure and host-testable.

#pragma once

#include <cstdint>

#include "tag.h"

namespace orthrus::credential {

enum class Severity : uint8_t { Info = 0, Low, Medium, High, Critical };

enum class FindingId : uint8_t {
    // --- proven by probing: we did the thing and it worked ------------------
    DefaultKeyAccepted,    // a published key opened a sector. Not an opinion.
    ReadableWithoutAuth,   // user memory came out with no key at all

    // --- inherent to what the card is ---------------------------------------
    NoCryptography,        // Ultralight/NTAG: nothing to authenticate with
    BrokenCipher,          // Crypto1, publicly broken since 2008
    ClassicSectorsPresent, // strong card carrying weak sectors as well
    WeakCipher,            // single/triple DES
    PasswordOnlyProtection,// 32 bits of shared secret, not a cipher
    ClonableUid,           // 4-byte UID, and blank cards accept any of them

    // --- meta: the thing we cannot see --------------------------------------
    ReaderPolicyUnknown,   // always present, and always the real answer
    DeeperProbeNotRun,     // we did not try keys, so absence proves nothing
};

struct Finding {
    FindingId id;
    Severity  sev;
    uint8_t   confidence;  // 0..97
};

// Nothing established by a contactless read is ever certain.
inline constexpr uint8_t kConfidenceCeiling = 97;

// A+ is unreachable from a read alone. See the note at the top of this file.
inline constexpr uint8_t kReadAloneCeiling = 92;

// Crypto1 has been broken in public for well over a decade. A card relying on
// it cannot be described as sound whatever else it does right.
inline constexpr uint8_t kBrokenCipherCeiling = 45;

// Nothing to authenticate against at all.
inline constexpr uint8_t kNoCryptoCeiling = 25;

// We opened it with a key printed in every tutorial on the subject.
inline constexpr uint8_t kDefaultKeyCeiling = 12;

struct FindingSet {
    static constexpr uint8_t kMax = 10;
    Finding items[kMax]{};
    uint8_t count = 0;

    bool add(FindingId id, Severity sev, uint8_t confidence);
    bool has(FindingId id) const;
    const Finding* get(FindingId id) const;
};

enum class Grade : uint8_t { APlus = 0, A, B, C, D, F };

struct Assessment {
    FindingSet findings;
    uint8_t    score = 100;
    Grade      grade = Grade::APlus;

    // True when the grade rests only on anticollision, with no key or read
    // probe attempted. The card may be far worse than this says.
    bool surfaceOnly = false;
};

Assessment assess(const TagIdentity& tag);

const char* findingTitle(FindingId id);
const char* findingDetail(FindingId id);
const char* severityName(Severity s);
const char* gradeName(Grade g);
Grade       scoreToGrade(uint8_t score);

// An Info finding describes the capture, not the card, so a percentage on it
// would be meaningless.
inline bool findingCarriesConfidence(Severity s) { return s != Severity::Info; }

}  // namespace orthrus::credential
