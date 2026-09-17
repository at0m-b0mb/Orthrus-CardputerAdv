// Wi-Fi networks, as a passive scan sees them, and how exposed they are.
//
// THE CEILING, AGAIN
//
// A scan shows you the beacon. It does not show you the passphrase, whether
// management frames are protected in practice, whether clients are isolated
// from each other, or whether this access point is the one it claims to be. All
// four of those decide whether a network is actually safe, and none of them are
// visible from outside.
//
// So no network earns A+ from a scan, and the device says why. What a scan CAN
// settle is decisive on its own: an open network is open, and WEP has been
// broken since 2001.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::wifi {

inline constexpr size_t kSsidLen = 33;  // 32 bytes plus terminator
inline constexpr size_t kBssidLen = 6;

enum class Security : uint8_t {
    Open = 0,
    Wep,
    WpaPsk,          // TKIP era
    Wpa2Psk,
    WpaWpa2Psk,      // mixed mode, so the WPA half is still reachable
    Wpa2Enterprise,
    Wpa3Sae,
    Wpa2Wpa3Mixed,   // transition mode: WPA2 still accepted
    Unknown,
};

struct Network {
    char     ssid[kSsidLen] = {0};
    uint8_t  bssid[kBssidLen] = {0};
    uint8_t  channel  = 0;
    int16_t  rssi     = 0;
    Security security = Security::Unknown;

    // A beacon with an empty SSID field. Not a security control -- clients then
    // shout the name themselves looking for it -- but worth reporting.
    bool hidden() const { return ssid[0] == '\0'; }

    // Beacons on channels above 14 are 5 GHz. The Cardputer's radio is 2.4 GHz
    // only, so seeing one at all would mean something is wrong.
    bool is24GHz() const { return channel >= 1 && channel <= 14; }
};

const char* securityName(Security s);

// True when the network accepts a connection with no key whatsoever.
bool isOpen(Security s);

// True when the encryption is broken rather than merely dated.
bool isBroken(Security s);

// ---- findings ---------------------------------------------------------------

enum class Severity : uint8_t { Info = 0, Low, Medium, High, Critical };

enum class FindingId : uint8_t {
    OpenNetwork,        // no encryption at all
    WepEncryption,      // broken in public since 2001
    WpaTkipReachable,   // the WPA half of a mixed-mode network
    Wpa2TransitionMode, // WPA3 advertised, WPA2 still accepted
    PreSharedKeyOnly,   // one key everyone holds
    HiddenNetwork,      // the name is not hidden, just moved onto the clients
    DuplicateSsid,      // same name, different radio: roaming, or a twin
    KeyStrengthUnknown, // meta: the thing that actually decides it
};

struct Finding {
    FindingId id;
    Severity  sev;
    uint8_t   confidence;
};

inline constexpr uint8_t kConfidenceCeiling = 97;
inline constexpr uint8_t kScanOnlyCeiling   = 92;  // A+ unreachable from a scan
inline constexpr uint8_t kOpenCeiling       = 15;
inline constexpr uint8_t kBrokenCeiling     = 30;

struct FindingSet {
    static constexpr uint8_t kMax = 8;
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
};

// `duplicateBssids` is how many OTHER radios were seen advertising this same
// SSID. The caller knows that; a single Network does not.
Assessment assess(const Network& n, uint8_t duplicateBssids = 0);

const char* findingTitle(FindingId id);
const char* findingDetail(FindingId id);
const char* severityName(Severity s);
const char* gradeName(Grade g);
Grade       scoreToGrade(uint8_t score);

inline bool findingCarriesConfidence(Severity s) { return s != Severity::Info; }

// Formats a BSSID as aa:bb:cc:dd:ee:ff. `out` needs 18 bytes.
void formatBssid(const uint8_t bssid[kBssidLen], char out[18]);

}  // namespace orthrus::wifi
