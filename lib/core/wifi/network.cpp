#include "network.h"

#include <cstdio>

namespace orthrus::wifi {
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

// A curve rather than a clip, so ordering survives beneath the ceiling: of two
// open networks, the one also broadcasting a duplicate SSID still ranks worse.
uint8_t applyCeiling(uint8_t score, uint8_t ceiling) {
    return static_cast<uint8_t>((static_cast<uint32_t>(ceiling) * score) / 100u);
}

}  // namespace

const char* securityName(Security s) {
    switch (s) {
        case Security::Open:           return "open";
        case Security::Wep:            return "WEP";
        case Security::WpaPsk:         return "WPA";
        case Security::Wpa2Psk:        return "WPA2";
        case Security::WpaWpa2Psk:     return "WPA/WPA2";
        case Security::Wpa2Enterprise: return "WPA2-Enterprise";
        case Security::Wpa3Sae:        return "WPA3";
        case Security::Wpa2Wpa3Mixed:  return "WPA2/WPA3";
        case Security::Unknown:        return "unknown";
    }
    return "?";
}

bool isOpen(Security s) { return s == Security::Open; }

bool isBroken(Security s) {
    // WEP is broken outright. WPA with TKIP is not "broken" in the same sense
    // but is comprehensively deprecated and should be treated as such.
    return s == Security::Wep || s == Security::WpaPsk;
}

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
        case FindingId::OpenNetwork:        return "No encryption";
        case FindingId::WepEncryption:      return "WEP";
        case FindingId::WpaTkipReachable:   return "WPA still accepted";
        case FindingId::Wpa2TransitionMode: return "WPA2 still accepted";
        case FindingId::PreSharedKeyOnly:   return "Shared passphrase";
        case FindingId::HiddenNetwork:      return "Hidden name";
        case FindingId::DuplicateSsid:      return "Name on several radios";
        case FindingId::KeyStrengthUnknown: return "Key strength not visible";
    }
    return "?";
}

const char* findingDetail(FindingId id) {
    switch (id) {
        case FindingId::OpenNetwork:
            return "Anyone in range joins without a key and reads every "
                   "unencrypted byte on the air.";
        case FindingId::WepEncryption:
            return "WEP has been broken in public since 2001. The key is "
                   "recovered from captured traffic in minutes.";
        case FindingId::WpaTkipReachable:
            return "Mixed mode leaves the old WPA half reachable, so an "
                   "attacker simply asks for the weaker one.";
        case FindingId::Wpa2TransitionMode:
            return "WPA3 is advertised but WPA2 is still accepted, so the "
                   "downgrade path is open.";
        case FindingId::PreSharedKeyOnly:
            return "One passphrase shared by everyone. Anyone who has ever had "
                   "it keeps access until it is changed for all.";
        case FindingId::HiddenNetwork:
            return "The name is not hidden, only moved: clients now broadcast "
                   "it wherever they go, looking for this network.";
        case FindingId::DuplicateSsid:
            return "Several radios advertise this name. Normal for roaming, "
                   "and also exactly what a twin looks like. A scan cannot "
                   "tell the two apart.";
        case FindingId::KeyStrengthUnknown:
            return "A scan sees the beacon, not the passphrase, client "
                   "isolation, or whether this really is the network it "
                   "claims. No scan can award full marks.";
    }
    return "";
}

Assessment assess(const Network& n, uint8_t duplicateBssids) {
    Assessment out;
    FindingSet& fs = out.findings;

    switch (n.security) {
        case Security::Open:
            fs.add(FindingId::OpenNetwork, Severity::Critical, 97);
            break;
        case Security::Wep:
            fs.add(FindingId::WepEncryption, Severity::Critical, 97);
            break;
        case Security::WpaPsk:
            fs.add(FindingId::WpaTkipReachable, Severity::High, 95);
            fs.add(FindingId::PreSharedKeyOnly, Severity::Low, 90);
            break;
        case Security::WpaWpa2Psk:
            fs.add(FindingId::WpaTkipReachable, Severity::High, 90);
            fs.add(FindingId::PreSharedKeyOnly, Severity::Low, 90);
            break;
        case Security::Wpa2Psk:
            fs.add(FindingId::PreSharedKeyOnly, Severity::Low, 90);
            break;
        case Security::Wpa2Wpa3Mixed:
            fs.add(FindingId::Wpa2TransitionMode, Severity::Medium, 90);
            break;
        case Security::Wpa2Enterprise:
        case Security::Wpa3Sae:
            break;  // nothing a scan can hold against these
        case Security::Unknown:
            break;
    }

    if (n.hidden()) {
        // Low, not Medium: it is bad practice rather than a way in, and the
        // real cost lands on the clients rather than the network.
        fs.add(FindingId::HiddenNetwork, Severity::Low, 85);
    }

    if (duplicateBssids > 0) {
        // Deliberately Medium and deliberately hedged. Enterprise roaming looks
        // identical to a twin from outside, and calling every multi-AP site an
        // attack would train the operator to ignore the finding.
        fs.add(FindingId::DuplicateSsid, Severity::Medium,
               duplicateBssids >= 3 ? 60 : 45);
    }

    // Always present, always free. It is the honest answer to "is this network
    // safe?" and it is why A+ cannot be reached.
    fs.add(FindingId::KeyStrengthUnknown, Severity::Info, 100);

    int32_t score = 100;
    for (uint8_t i = 0; i < fs.count; i++) {
        const Finding& f = fs.items[i];
        score -= (static_cast<int32_t>(severityWeight(f.sev)) * f.confidence) / 100;
    }
    if (score < 0) score = 0;
    uint8_t s = static_cast<uint8_t>(score);

    s = applyCeiling(s, kScanOnlyCeiling);
    if (isBroken(n.security)) s = applyCeiling(s, kBrokenCeiling);
    if (isOpen(n.security))   s = applyCeiling(s, kOpenCeiling);

    out.score = s;
    out.grade = scoreToGrade(s);
    return out;
}

void formatBssid(const uint8_t bssid[kBssidLen], char out[18]) {
    std::snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", bssid[0], bssid[1],
                  bssid[2], bssid[3], bssid[4], bssid[5]);
}

}  // namespace orthrus::wifi
