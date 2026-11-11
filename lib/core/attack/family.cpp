#include "attack/family.h"

#include <cstring>

namespace orthrus::attack {

namespace {

// The domain in force. File-scope because it is a property of where the device
// is standing, not of any one plan, and every surface must see the same answer.
Region g_region = Region::Fcc;

bool macIsZero(const uint8_t a[kMacLen]) {
    for (size_t i = 0; i < kMacLen; i++)
        if (a[i]) return false;
    return true;
}

// Broadcast, multicast, or all-zero: never one real station.
bool macIsGroup(const uint8_t a[kMacLen]) {
    if (macIsZero(a)) return true;
    return (a[0] & 0x01) != 0;
}

// ---- the table --------------------------------------------------------------
//
// Ordered by group so that reading the table and reading the picker are the
// same exercise. Every row has an `effect` written for the person holding the
// device, not for the report.

constexpr Spec kSpecs[] = {
    // --- Impersonate ---------------------------------------------------------
    {"Beacons",
     "Whether anything in the room notices access points that were not there "
     "a minute ago.",
     "Adds invented networks to every nearby device's Wi-Fi list. Denies "
     "nothing and disconnects nobody.",
     Klass::Benign, Group::Impersonate, Radio::Wifi,
     /*needsTarget*/ false, /*needsClient*/ false, /*popsDialog*/ false,
     /*pps*/ 10, /*maxPps*/ 50, /*maxSeconds*/ 120},

    {"Twin beacon",
     "Whether this network's clients can tell the real access point from one "
     "shouting the same name.",
     "Puts the target's own name and address on the air with the wrong "
     "security. Clients may try to join it instead and fail to get online.",
     Klass::Active, Group::Impersonate, Radio::Wifi,
     true, false, false, 10, 50, 120},

    {"Karma",
     "Which networks the devices in this room are still looking for -- and "
     "whether any of them will accept an answer from a stranger.",
     "Answers other people's probes, so their devices believe a network they "
     "trust is here. It logs who asked for what. It never asks for a "
     "password.",
     Klass::Active, Group::Impersonate, Radio::Wifi,
     false, false, false, 20, 100, 300},

    // --- Capture -------------------------------------------------------------
    {"PMKID",
     "Whether this access point hands crackable key material to anyone who "
     "asks, with no client involved at all.",
     "Asks the access point to associate, repeatedly, and keeps what it "
     "volunteers. Clients stay online throughout.",
     Klass::Active, Group::Capture, Radio::Wifi,
     true, false, false, 2, 5, 60},

    // --- Disrupt -------------------------------------------------------------
    {"Deauth",
     "Whether forged disconnects are accepted -- that is, whether 802.11w is "
     "actually protecting this network.",
     "Everyone on this network drops off it and has to rejoin. Calls, video "
     "and anything mid-upload will fail.",
     Klass::Disruptive, Group::Disrupt, Radio::Wifi,
     true, false, false, 20, 100, 30},

    {"Disassoc",
     "The same question as Deauth, by the other frame -- some stacks honour "
     "one and ignore the other.",
     "Everyone on this network drops off it and has to rejoin. Calls, video "
     "and anything mid-upload will fail.",
     Klass::Disruptive, Group::Disrupt, Radio::Wifi,
     true, false, false, 20, 100, 30},

    {"Auth flood",
     "Whether the access point's association table can be filled by a "
     "stranger until real clients cannot get in.",
     "New devices stop being able to join. Devices already on the network "
     "usually stay on it.",
     Klass::Disruptive, Group::Disrupt, Radio::Wifi,
     true, false, false, 50, 200, 30},

    {"Assoc flood",
     "The same question, one step further into the handshake, which some "
     "access points handle and others do not.",
     "New devices stop being able to join, and the access point may restart "
     "its radio.",
     Klass::Disruptive, Group::Disrupt, Radio::Wifi,
     true, false, false, 20, 100, 30},

    {"Channel switch",
     "Whether clients obey an unauthenticated instruction to move to another "
     "channel, and so can be walked away from their own network.",
     "Clients move to a channel the access point is not on and lose it "
     "entirely, often for longer than the test runs.",
     Klass::Disruptive, Group::Disrupt, Radio::Wifi,
     true, false, false, 5, 20, 30},

    // --- Emulate -------------------------------------------------------------
    {"Find My",
     "Whether a tracker detector recognises Apple offline-finding when it "
     "hears it.",
     "Nearby iPhones may relay this to Apple as a lost item. Their owners see "
     "nothing.",
     Klass::Benign, Group::Emulate, Radio::Ble,
     false, false, false, 10, 20, 300},

    {"Tile",
     "Whether a tracker detector recognises a Tile.",
     "Nothing visible to anyone nearby. Detectors and the Tile app may list "
     "it.",
     Klass::Benign, Group::Emulate, Radio::Ble,
     false, false, false, 10, 20, 300},

    {"SmartTag",
     "Whether a tracker detector recognises a Samsung SmartTag.",
     "Nothing visible to anyone nearby. Nearby Galaxy phones may relay it.",
     Klass::Benign, Group::Emulate, Radio::Ble,
     false, false, false, 10, 20, 300},

    {"Fast Pair",
     "Whether a device-spam detector sees a Google Fast Pair solicitation.",
     "A PAIRING DIALOG APPEARS on nearby Android phones, in the hands of "
     "people who did not ask for it. Use it where you have told them.",
     Klass::Active, Group::Emulate, Radio::Ble,
     false, false, /*popsDialog*/ true, 5, 10, 60},

    {"Swift Pair",
     "Whether a device-spam detector sees a Microsoft Swift Pair "
     "solicitation.",
     "A PAIRING NOTIFICATION APPEARS on nearby Windows machines, in front of "
     "people who did not ask for it.",
     Klass::Active, Group::Emulate, Radio::Ble,
     false, false, /*popsDialog*/ true, 5, 10, 60},

    {"Flipper",
     "Whether a detector that keys on advertised names spots a Flipper Zero.",
     "Nothing visible to anyone nearby. Apps that hunt for Flippers will "
     "list it.",
     Klass::Benign, Group::Emulate, Radio::Ble,
     false, false, false, 10, 20, 300},

    {"Swarm",
     "Whether a detector holds up when many distinct identities appear at "
     "once, which is what real advertisement spam looks like.",
     "Fills nearby devices' Bluetooth lists. The two pairing families are "
     "excluded from the rotation, so no dialog is raised.",
     Klass::Active, Group::Broadcast, Radio::Ble,
     false, false, false, 20, 50, 120},
};

static_assert(sizeof(kSpecs) / sizeof(kSpecs[0]) ==
                  static_cast<size_t>(Family::Count),
              "every Family needs exactly one row, in enum order");

}  // namespace

const Spec* spec(Family f) {
    const size_t i = static_cast<size_t>(f);
    if (i >= static_cast<size_t>(Family::Count)) return nullptr;
    return &kSpecs[i];
}

const char* familyName(Family f) {
    const Spec* s = spec(f);
    return s ? s->name : "?";
}

bool isBle(Family f) {
    const Spec* s = spec(f);
    return s != nullptr && s->radio == Radio::Ble;
}

const char* groupName(Group g) {
    switch (g) {
        case Group::Disrupt:     return "Disrupt";
        case Group::Capture:     return "Capture";
        case Group::Impersonate: return "Impersonate";
        case Group::Emulate:     return "Emulate";
        case Group::Broadcast:   return "Broadcast";
        case Group::Count:       break;
    }
    return "?";
}

const char* groupBlurb(Group g) {
    switch (g) {
        case Group::Disrupt:     return "Stop something real from working";
        case Group::Capture:     return "Take key material off the target";
        case Group::Impersonate: return "Pretend to be a network";
        case Group::Emulate:     return "Pretend to be a specific product";
        case Group::Broadcast:   return "Put shaped traffic on the air";
        case Group::Count:       break;
    }
    return "";
}

const char* klassName(Klass k) {
    switch (k) {
        case Klass::Benign:     return "benign";
        case Klass::Active:     return "active";
        case Klass::Disruptive: return "disruptive";
    }
    return "?";
}

const char* radioName(Radio r) {
    switch (r) {
        case Radio::Wifi: return "Wi-Fi";
        case Radio::Ble:  return "Bluetooth";
    }
    return "?";
}

// ---- the authorisation ------------------------------------------------------

bool Authorization::valid(uint32_t nowMs) const {
    if (!locked) return false;
    if (ttlMs == 0) return false;
    // Unsigned subtraction, so a millisecond counter that has wrapped since the
    // lock was taken still yields the elapsed time rather than a huge number.
    return static_cast<uint32_t>(nowMs - grantedMs) < ttlMs;
}

uint32_t Authorization::remainingMs(uint32_t nowMs) const {
    if (!valid(nowMs)) return 0;
    return ttlMs - static_cast<uint32_t>(nowMs - grantedMs);
}

bool lock(Authorization& a, const char* ssid, const uint8_t bssid[kMacLen],
          uint8_t channel, uint32_t nowMs, uint32_t ttlMs) {
    if (bssid == nullptr) return false;
    // A group or all-zero BSSID is not a target, it is everybody. Refusing here
    // is the difference between "one network, chosen by hand" being a doctrine
    // and being a sentence in a README.
    if (macIsGroup(bssid)) return false;
    if (channel < 1 || channel > 14) return false;
    if (ttlMs == 0) return false;

    a = Authorization{};
    if (ssid != nullptr) {
        std::strncpy(a.ssid, ssid, kSsidBuf - 1);
        a.ssid[kSsidBuf - 1] = '\0';
    }
    std::memcpy(a.bssid, bssid, kMacLen);
    a.channel   = channel;
    a.grantedMs = nowMs;
    a.ttlMs     = ttlMs > kMaxTtlMs ? kMaxTtlMs : ttlMs;
    a.locked    = true;
    return true;
}

bool lockClient(Authorization& a, const uint8_t client[kMacLen]) {
    if (!a.locked) return false;
    if (client == nullptr) {
        // Widening back to the cell is always allowed: it is the state the lock
        // started in.
        a.haveClient = false;
        std::memset(a.client, 0, kMacLen);
        return true;
    }
    if (macIsGroup(client)) return false;  // a broadcast in a station's clothes
    std::memcpy(a.client, client, kMacLen);
    a.haveClient = true;
    return true;
}

void unlock(Authorization& a) { a = Authorization{}; }

Scope scopeOf(const Authorization& a) {
    // ONE field decides this. There is no second "whole cell" flag to disagree
    // with it, which is the whole reason this function exists.
    return a.haveClient ? Scope::OneClient : Scope::WholeCell;
}

const char* scopeName(Scope s) {
    switch (s) {
        case Scope::WholeCell: return "whole cell";
        case Scope::OneClient: return "one client";
    }
    return "?";
}

void destinationFor(const Authorization& a, uint8_t out[kMacLen]) {
    if (out == nullptr) return;
    if (scopeOf(a) == Scope::OneClient) {
        std::memcpy(out, a.client, kMacLen);
        return;
    }
    std::memset(out, 0xFF, kMacLen);
}

// ---- the plan ---------------------------------------------------------------

void planDefault(Plan& p, Family f) {
    p = Plan{};
    p.family = f;
    const Spec* s = spec(f);
    if (s == nullptr) return;
    p.pps     = s->defaultPps;
    p.seconds = s->maxSeconds;
    // Only the long-running observational families default to running until
    // the operator stops them. Nothing disruptive does.
    p.continuous = false;
}

const char* planErrorText(PlanError e) {
    switch (e) {
        case PlanError::Ok:                   return "ready";
        case PlanError::UnknownFamily:        return "unknown family";
        case PlanError::NotAuthorized:        return "no target locked";
        case PlanError::AuthorizationExpired: return "authorisation expired";
        case PlanError::NoTarget:             return "this needs an access point";
        case PlanError::NoClient:             return "this needs one station";
        case PlanError::ChannelRefused:       return "channel outside your region";
    }
    return "?";
}

PlanError validate(Plan& p, const Authorization& a, uint32_t nowMs) {
    const Spec* s = spec(p.family);
    if (s == nullptr) return PlanError::UnknownFamily;

    // UNCONDITIONAL, AND FIRST.
    //
    // This check used to sit inside the `needsTarget` branch below, which meant
    // every family with needsTarget false -- that is, every Bluetooth family --
    // transmitted without any authorisation ever being consulted. The families
    // that need no target are exactly the ones that most look like they need no
    // permission, which is why the check goes here and not there.
    if (!a.locked) return PlanError::NotAuthorized;
    if (!a.valid(nowMs)) return PlanError::AuthorizationExpired;

    if (s->needsTarget) {
        if (macIsZero(a.bssid) || a.channel == 0) return PlanError::NoTarget;
    }
    if (s->needsClient && !a.haveClient) return PlanError::NoClient;

    // Which channel this will actually sit on: the plan's, or the target's.
    const uint8_t ch = p.channel != 0 ? p.channel : a.channel;
    if (s->radio == Radio::Wifi && ch != 0 && !regionAllows(ch))
        return PlanError::ChannelRefused;

    // Clamp only now that the run is permitted, so a refused plan is never
    // left half-modified for a caller that ignores the return value.
    p.clampedPps     = false;
    p.clampedSeconds = false;

    if (p.pps == 0) p.pps = s->defaultPps;
    if (p.pps > s->maxPps) {
        p.pps = s->maxPps;
        p.clampedPps = true;
    }

    if (p.continuous) {
        // Not unbounded: the authorisation is re-checked before every burst and
        // its TTL is capped, so "until stopped" cannot become "until the
        // battery dies in a drawer".
        p.seconds = 0;
    } else {
        if (p.seconds == 0) p.seconds = s->maxSeconds;
        if (p.seconds > s->maxSeconds) {
            p.seconds = s->maxSeconds;
            p.clampedSeconds = true;
        }
    }

    return PlanError::Ok;
}

uint32_t frameBudget(const Plan& p) {
    if (p.continuous || p.seconds == 0) return 0;
    const Spec* s = spec(p.family);
    if (s == nullptr) return 0;
    // Guard rather than trust: a plan that never went through validate() may
    // carry a rate above the ceiling, and a budget is shown to an operator.
    uint32_t pps = p.pps;
    if (pps > s->maxPps) pps = s->maxPps;
    uint32_t secs = p.seconds;
    if (secs > s->maxSeconds) secs = s->maxSeconds;
    return pps * secs;
}

// ---- the regulatory clamp ---------------------------------------------------

void   regionSet(Region r) { g_region = r; }
Region regionGet() { return g_region; }

uint8_t regionMaxChannel() {
    switch (g_region) {
        case Region::Fcc:  return 11;
        case Region::Etsi: return 13;
        case Region::Jp:   return 14;
    }
    return 11;
}

const char* regionName(Region r) {
    switch (r) {
        case Region::Fcc:  return "FCC 1-11";
        case Region::Etsi: return "ETSI 1-13";
        case Region::Jp:   return "JP 1-14";
    }
    return "?";
}

bool regionAllows(uint8_t channel) {
    if (channel < 1) return false;
    return channel <= regionMaxChannel();
}

Region regionFromCountry(const char* cc) {
    if (cc == nullptr || cc[0] == '\0' || cc[1] == '\0') return Region::Fcc;

    const char a = static_cast<char>(cc[0] >= 'a' && cc[0] <= 'z' ? cc[0] - 32 : cc[0]);
    const char b = static_cast<char>(cc[1] >= 'a' && cc[1] <= 'z' ? cc[1] - 32 : cc[1]);

    if (a == 'J' && b == 'P') return Region::Jp;

    // The FCC plan, 1..11. Not an exhaustive list of the world: an unknown code
    // falls through to the same answer, so a missing entry refuses a channel
    // rather than authorising one.
    static const char* const kFcc[] = {"US", "CA", "MX", "BR", "CO", "TW", "PH"};
    for (const char* c : kFcc)
        if (a == c[0] && b == c[1]) return Region::Fcc;

    // Everything else that is known: 1..13.
    static const char* const kEtsi[] = {"GB", "IE", "FR", "DE", "ES", "IT", "NL",
                                        "BE", "AT", "CH", "SE", "NO", "DK", "FI",
                                        "PL", "PT", "GR", "CZ", "IN", "AU", "NZ",
                                        "SG", "MY", "ZA", "AE", "IL", "KR", "CN",
                                        "HK", "TH", "ID", "VN", "TR", "RU", "UA"};
    for (const char* c : kEtsi)
        if (a == c[0] && b == c[1]) return Region::Etsi;

    return Region::Fcc;
}

Region regionForChannel(uint8_t channel) {
    if (channel >= 1 && channel <= 11) return Region::Fcc;
    if (channel == 12 || channel == 13) return Region::Etsi;
    if (channel == 14) return Region::Jp;
    return Region::Fcc;
}

bool regionWidenFor(uint8_t channel) {
    if (channel < 1 || channel > 14) return false;
    const Region need = regionForChannel(channel);
    // Never narrow. The enum happens to be ordered narrowest-first, which is
    // relied on here and nowhere else, so the comparison says what it means.
    if (static_cast<uint8_t>(need) <= static_cast<uint8_t>(g_region)) return false;
    g_region = need;
    return true;
}

// ---- the test prefix --------------------------------------------------------

bool labelOk(const char* label) {
    if (label == nullptr) return false;
    const char* p = ORTHRUS_TEST_PREFIX;
    size_t i = 0;
    for (; p[i] != '\0'; i++) {
        if (label[i] != p[i]) return false;
    }
    // The prefix alone is not a name. Something has to follow it, or two
    // different invented networks are indistinguishable on a scanner.
    return label[i] != '\0';
}

bool familyMayImpersonate(Family f) {
    switch (f) {
        // Carries the target's own name and BSSID. That IS the test: a client
        // that cannot tell this from the real access point is the finding.
        case Family::TwinBeacon:
        // Answers with whatever name was asked for, which is somebody else's.
        case Family::Karma:
        // Carry the vendor's own company identifier or service UUID. A
        // classifier keying on 0x004C will correctly ignore the SIG's reserved
        // test identifier, so a test built from it proves nothing.
        case Family::BleFindMy:
        case Family::BleTile:
        case Family::BleSmartTag:
        case Family::BleFastPair:
        case Family::BleSwiftPair:
        case Family::BleFlipper:
        case Family::BleSwarm:
            return true;
        default:
            return false;
    }
}

}  // namespace orthrus::attack
