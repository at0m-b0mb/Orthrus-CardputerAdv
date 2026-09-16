// Turning observed behaviour into graded findings.
//
// The governing rule, and the reason this file is separate from the census:
//
//   PRESENCE IS PROOF. ABSENCE IS NOT.
//
// If we saw a frame counter go backwards, we saw it, and no amount of missed
// spectrum makes that less true -- so it scores at full weight. If we never saw
// a device join, that is not evidence it does not join: one SX1262 camps on one
// channel at one spreading factor, roughly 1/48 of EU868. Findings that argue
// from absence are therefore capped by how much of the band we could actually
// hear, and below a coverage floor they are not emitted at all. Instead the
// tool says plainly that it cannot tell.
//
// That last behaviour is deliberate. A scanner that stays quiet about its blind
// spots produces confident nonsense, and a client can tell.

#pragma once

#include <cstdint>

#include "census.h"

namespace orthrus::lorawan {

enum class Severity : uint8_t {
    Info = 0,
    Low,
    Medium,
    High,
    Critical,
};

enum class FindingId : uint8_t {
    // --- presence-based: we observed the thing happen ---
    FCntReset,            // counter went backwards without wrapping
    FCntRepeat,           // same counter twice
    DevNonceReuse,        // join nonce repeated inside the window
    PlaintextPayload,     // FRMPayload is not ciphertext
    FPortZeroWithFOpts,   // MAC commands in two places at once: spec violation
    AdrDisabled,          // device never sets ADR
    ConfirmedUplinkHeavy, // every uplink demands a downlink
    JoinChurn,            // rejoining far more often than a healthy device
    StuckHighSF,          // only ever heard at SF11/SF12

    // --- absence-based: capped, or suppressed entirely ---
    AbpSuspected,         // never seen to join

    // --- meta ---
    CoverageTooLow,       // we cannot assess absence at all; say so
};

struct Finding {
    FindingId id;
    Severity  sev;
    uint8_t   confidence;  // 0..97
};

// Nothing we produce from a passive receiver without keys is ever certain.
inline constexpr uint8_t kGlobalConfidenceCeiling = 97;

// Absence-based findings can never exceed this, however long we listen.
inline constexpr uint8_t kAbsenceCeiling = 35;

// Below this much of the channel/SF space, absence findings are suppressed and
// replaced by CoverageTooLow.
inline constexpr uint8_t kMinCoverageForAbsence = 20;

struct FindingSet {
    static constexpr uint8_t kMax = 12;
    Finding items[kMax]{};
    uint8_t count = 0;

    bool add(FindingId id, Severity sev, uint8_t confidence);
    bool has(FindingId id) const;
    const Finding* get(FindingId id) const;
};

// A..F letter grade, the way the rest of the catalogue reports.
enum class Grade : uint8_t { APlus = 0, A, B, C, D, F };

struct DeviceAssessment {
    FindingSet findings;
    uint8_t    score = 100;  // 0..100 before letter mapping
    Grade      grade = Grade::APlus;
};

DeviceAssessment assess(const DeviceRecord& device, const CaptureContext& ctx);

const char* findingTitle(FindingId id);
const char* findingDetail(FindingId id);
const char* severityName(Severity s);
const char* gradeName(Grade g);

Grade scoreToGrade(uint8_t score);

}  // namespace orthrus::lorawan
