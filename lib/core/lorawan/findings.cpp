#include "findings.h"

namespace orthrus::lorawan {
namespace {

// Score cost of a finding at full confidence. Scaled by confidence at use.
uint8_t severityWeight(Severity s) {
    switch (s) {
        case Severity::Critical: return 45;
        case Severity::High:     return 30;
        case Severity::Medium:   return 15;
        case Severity::Low:      return 6;
        case Severity::Info:     return 0;
    }
    return 0;
}

uint8_t clampConfidence(uint8_t c) {
    return c > kGlobalConfidenceCeiling ? kGlobalConfidenceCeiling : c;
}

// A ceiling applied as a curve rather than a clip.
//
// Clipping at, say, 45 would make a device with one marginal issue and a device
// riddled with them score identically. Scaling instead keeps the ordering
// intact underneath the ceiling, so the worst device is still visibly the worst
// -- the same approach Sibyl uses for its honesty ceilings.
uint8_t applyCeiling(uint8_t score, uint8_t ceiling) {
    const uint32_t scaled = (static_cast<uint32_t>(ceiling) * score) / 100u;
    return static_cast<uint8_t>(scaled);
}

// Fewer frames than this and the counter history is too thin to judge. We can
// still report what we saw; we must not award a top grade for it.
constexpr uint32_t kMinFramesForFullGrade = 5;
constexpr uint8_t  kThinEvidenceCeiling   = 84;  // B

constexpr uint8_t kPlaintextCeiling = 45;  // D
constexpr uint8_t kReplayCeiling    = 60;  // C

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
        case FindingId::FCntReset:            return "Frame counter reset";
        case FindingId::FCntRepeat:           return "Frame counter repeated";
        case FindingId::DevNonceReuse:        return "Join nonce reused";
        case FindingId::PlaintextPayload:     return "Payload not encrypted";
        case FindingId::FPortZeroWithFOpts:   return "MAC commands in two places";
        case FindingId::AdrDisabled:          return "ADR never set";
        case FindingId::ConfirmedUplinkHeavy: return "Every uplink confirmed";
        case FindingId::JoinChurn:            return "Rejoining repeatedly";
        case FindingId::StuckHighSF:          return "Stuck at high spreading factor";
        case FindingId::AbpSuspected:         return "Possibly ABP";
        case FindingId::CoverageTooLow:       return "Coverage too low to judge";
    }
    return "?";
}

const char* findingDetail(FindingId id) {
    switch (id) {
        case FindingId::FCntReset:
            return "The counter went backwards without wrapping. Every frame "
                   "below the old value can now be replayed and accepted.";
        case FindingId::FCntRepeat:
            return "The same counter was seen twice. That is either a "
                   "retransmission or a replay; the air alone cannot say which.";
        case FindingId::DevNonceReuse:
            return "A join nonce repeated. In LoRaWAN 1.0.x this allows a "
                   "captured join request to be replayed against the network.";
        case FindingId::PlaintextPayload:
            return "FRMPayload is readable without keys, so the application "
                   "data is exposed to anyone in range.";
        case FindingId::FPortZeroWithFOpts:
            return "MAC commands appear in FRMPayload and FOpts at once, which "
                   "the spec forbids. The stack is broken or being manipulated.";
        case FindingId::AdrDisabled:
            return "ADR was never set, so the device cannot be moved to a "
                   "faster rate. It burns airtime and battery.";
        case FindingId::ConfirmedUplinkHeavy:
            return "Nearly every uplink is confirmed, forcing a downlink each "
                   "time. That is expensive and is an amplification surface.";
        case FindingId::JoinChurn:
            return "The device rejoins far more than a healthy one, which "
                   "suggests instability or interference.";
        case FindingId::StuckHighSF:
            return "Only heard at SF11/SF12: maximum airtime, minimum battery "
                   "life, and the loudest possible footprint.";
        case FindingId::AbpSuspected:
            return "No join was observed. This is weak evidence on its own -- "
                   "one radio hears a fraction of the band.";
        case FindingId::CoverageTooLow:
            return "Too little of the channel/SF space was covered to say "
                   "anything about what was NOT heard. Dwell longer or sweep.";
    }
    return "";
}

DeviceAssessment assess(const DeviceRecord& d, const CaptureContext& ctx) {
    DeviceAssessment out;
    FindingSet& fs = out.findings;

    const uint8_t coverage = ctx.coveragePercent();
    const bool canJudgeAbsence = coverage >= kMinCoverageForAbsence;

    // ---- presence-based: observed, therefore scored at full weight ----------

    // Each direction's counter is judged on its own. Comparing an uplink
    // counter against a downlink one is meaningless -- they are independent
    // sequences -- and doing so turned ordinary ACK traffic into a dozen false
    // Critical findings on a device that was behaving perfectly.
    const uint32_t resets  = d.up.resets + d.down.resets;
    const uint32_t repeats = d.up.repeats + d.down.repeats;

    if (resets > 0) {
        // Seeing this even once is decisive; seeing it repeatedly is not more
        // decisive, it is just more embarrassing.
        fs.add(FindingId::FCntReset, Severity::Critical, 95);
    }

    if (repeats > 0) {
        // Ambiguous by nature, so confidence rises with how often it happened:
        // one repeat is a retransmission, ten is a pattern.
        const uint8_t conf = repeats >= 5 ? 75 : 50;
        fs.add(FindingId::FCntRepeat, Severity::Medium, conf);
    }

    if (d.devNonceRepeats > 0) {
        fs.add(FindingId::DevNonceReuse, Severity::High, 90);
    }

    if (d.plaintextCount > 0 && d.bestPlaintextConfidence > 0) {
        fs.add(FindingId::PlaintextPayload, Severity::High,
               d.bestPlaintextConfidence);
    }

    if (d.fPortZeroWithFOptsCount > 0) {
        fs.add(FindingId::FPortZeroWithFOpts, Severity::Medium, 90);
    }

    // "Never set ADR" is technically an absence, but it is an absence *within
    // frames we did receive* rather than across spectrum we could not hear, so
    // it is not coverage-limited. Counted on uplinks only: the ADR bit in a
    // downlink is the network talking, not the device.
    if (d.kind == DeviceKind::Session && d.adrSetCount == 0 &&
        d.adrClearCount >= kMinFramesForFullGrade) {
        fs.add(FindingId::AdrDisabled, Severity::Low, 80);
    }

    // Ratio of confirmed uplinks to uplinks -- not to all frames. Including
    // downlinks in the denominator quietly halved the ratio for any device the
    // network answered, which is most of them.
    if (d.kind == DeviceKind::Session && d.uplinkCount >= kMinFramesForFullGrade &&
        d.confirmedUplinkCount * 100u >= d.uplinkCount * 80u) {
        fs.add(FindingId::ConfirmedUplinkHeavy, Severity::Low, 75);
    }

    if (d.kind == DeviceKind::Joiner && d.joinCount >= 5) {
        fs.add(FindingId::JoinChurn, Severity::Medium, 70);
    }

    // Only claimable if we actually swept more than one spreading factor.
    // Parked on SF12, every device we are capable of hearing is at SF12 -- so
    // this finding would fire on the whole census and be describing our own
    // tuning rather than anything about the devices.
    if (ctx.canJudgeSpreadingFactor() && d.sfMin != 0xFF && d.sfMin >= 11 &&
        d.framesSeen >= 3) {
        fs.add(FindingId::StuckHighSF, Severity::Low, 70);
    }

    // ---- absence-based: capped, or refused outright -------------------------

    if (d.kind == DeviceKind::Session && d.framesSeen >= kMinFramesForFullGrade) {
        if (!canJudgeAbsence) {
            fs.add(FindingId::CoverageTooLow, Severity::Info, 100);
        } else {
            // Even at full coverage this stays weak: OTAA devices join rarely,
            // so a quiet capture proves very little.
            uint32_t conf = (60u * coverage) / 100u;
            if (ctx.listenedMs > 10u * 60u * 1000u && d.framesSeen >= 20) conf += 8;
            if (conf > kAbsenceCeiling) conf = kAbsenceCeiling;
            fs.add(FindingId::AbpSuspected, Severity::Low,
                   static_cast<uint8_t>(conf));
        }
    }

    // ---- score --------------------------------------------------------------

    int32_t score = 100;
    for (uint8_t i = 0; i < fs.count; i++) {
        const Finding& f = fs.items[i];
        const int32_t cost =
            (static_cast<int32_t>(severityWeight(f.sev)) * f.confidence) / 100;
        score -= cost;
    }
    if (score < 0) score = 0;
    uint8_t s = static_cast<uint8_t>(score);

    // Ceilings, as curves. A device leaking cleartext cannot be a B however
    // tidy its counters are.
    if (fs.has(FindingId::PlaintextPayload)) s = applyCeiling(s, kPlaintextCeiling);
    if (fs.has(FindingId::FCntReset))        s = applyCeiling(s, kReplayCeiling);

    // Thin evidence cannot earn a top grade, however clean it looks.
    if (d.framesSeen < kMinFramesForFullGrade && s > kThinEvidenceCeiling)
        s = kThinEvidenceCeiling;

    out.score = s;
    out.grade = scoreToGrade(s);

    // The grade is as good as the evidence under it. Say so rather than letting
    // an A+ from 16% of the band read like an A+ from all of it.
    out.provisional = (coverage < kMinCoverageForAbsence) ||
                      (d.framesSeen < kMinFramesForFullGrade);
    return out;
}

}  // namespace orthrus::lorawan
