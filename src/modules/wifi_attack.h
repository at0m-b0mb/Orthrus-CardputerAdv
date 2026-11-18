// Attack: transmit against one network the operator chose by hand.
//
// WHY THIS IS ONE SURFACE AND NOT NINE
//
// There are nine things this device can put on the 2.4 GHz air, and they share
// almost everything: pick a target, pick what to do to it, read what it will do
// to the people on it, hold a key to arm, watch it run, read what was actually
// observed. Nine modules would have been nine copies of that, and nine places
// for the arming doctrine to drift apart. The families come from
// attack/family.h, which is pure and tested, so this file is the screens and
// the radio and nothing else that decides anything.
//
// THE SHAPE OF AN ASSESSMENT, NOT A BUTTON
//
//   1. One target, chosen from a scan. The authorisation locks onto that one
//      access point, with a TTL, and every family is checked against it --
//      including the ones that need no target, because those are exactly the
//      ones that look like they need no permission.
//   2. The arming screen leads with EFFECT: what this does to the people on
//      that network, in their language. A frame count and a rate are both true
//      and neither says that everybody in the building is about to drop off.
//   3. A key held for two seconds, not tapped. A slip of the thumb should not
//      deauthenticate a floor.
//   4. Then it runs, bounded by the family's own ceiling, and stops on its own.
//   5. And it reports what was OBSERVED. Frames accepted by the driver are not
//      frames anybody received; clients coming back is evidence the forgery
//      worked, and silence is not evidence it did not.
//
// WHAT IT WILL NOT DO
//
//   No "all networks" mode. That is not a test of anything -- it is
//   interference with neighbours who did not agree to it and whose equipment is
//   in nobody's scope.
//
//   No captive portal and no credential prompt. Karma answers probes and logs
//   who asked for what; it never asks anybody for a password. That is the one
//   exclusion in this file that has never moved, and it is why Karma is here at
//   all: the finding is "your devices still trust this name", which needs no
//   harvesting to establish.
//
//   Nothing invented wears a real name. Every SSID this device makes up carries
//   the ORTHRUS- prefix, so anybody else sniffing the room sees a test rig. The
//   two exceptions -- Twin beacon and Karma -- exist precisely to carry
//   somebody else's name, and attack::familyMayImpersonate says so by name.

#pragma once

#include <cstdint>

#include "attack/family.h"
#include "dot11/capture.h"
#include "dot11/frame.h"
#include "dot11/inject.h"

namespace orthrus::modules {

class WifiAttack {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t {
        Unavailable,   // the raw-transmit override did not link
        Networks,
        Families,
        Arm,
        Running,
        Result,
    };

    static constexpr uint8_t kMaxNetworks = 24;

    // How long the authorisation lasts once a target is picked. An hour is
    // longer than any run the ceilings permit and short enough that a device
    // left in a bag stops being armed.
    static constexpr uint32_t kAuthTtlMs = 60u * 60u * 1000u;

    // Held, not tapped.
    static constexpr uint32_t kArmHoldMs = 2000;

    // How long to listen after a disruptive run for clients coming back.
    static constexpr uint32_t kWatchMs = 8000;

    // Invented access points per beacon pass.
    static constexpr uint8_t kInventedAps = 6;

    struct Network {
        char    ssid[dot11::kSsidBuf] = {0};
        uint8_t bssid[dot11::kMacLen] = {0};
        uint8_t channel = 0;
        int8_t  rssi    = 0;
        bool    secured = false;   // anything other than an open network
    };

    // ---- flow ---------------------------------------------------------------
    void startScan();
    void collectScan();
    bool lockSelected();
    void enterFamilies();
    void enterArm();
    bool armIfHeld();
    void startRun();
    void stepRun();
    void stepWatch();
    void finish();

    // One burst of whichever family is armed. Returns frames the driver
    // accepted.
    uint32_t emitBurst(uint16_t want);

    uint32_t emitBeacons(uint16_t want);
    uint32_t emitTwin(uint16_t want);
    uint32_t emitKarma(uint16_t want);
    uint32_t emitPmkid(uint16_t want);
    uint32_t emitDisconnect(uint16_t want, bool disassoc);
    uint32_t emitAuthFlood(uint16_t want);
    uint32_t emitAssocFlood(uint16_t want);
    uint32_t emitCsa(uint16_t want);

    bool savePmkid();

    // ---- screens ------------------------------------------------------------
    void drawUnavailable();
    void drawNetworks();
    void drawFamilies();
    void drawArm();
    void drawRunning();
    void drawResult();
    void draw();
    bool handleKeys();

    // ---- state --------------------------------------------------------------
    Network nets_[kMaxNetworks];
    uint8_t count_    = 0;
    int     selected_ = 0;
    int     scroll_   = 0;

    bool     scanning_    = false;
    uint32_t scanStarted_ = 0;

    int  family_       = 0;   // index into the Wi-Fi family list
    int  familyScroll_ = 0;

    attack::Authorization auth_;
    attack::Plan          plan_;
    attack::PlanError     planError_ = attack::PlanError::NotAuthorized;

    // The arming hold.
    uint32_t holdStart_ = 0;
    bool     holding_   = false;

    bool     widenedRegion_ = false;   // the target pulled the clamp open

    uint32_t runStart_   = 0;
    uint32_t lastTickMs_ = 0;
    uint32_t framesSent_ = 0;
    uint32_t framesFailed_ = 0;
    bool     watching_   = false;
    uint32_t watchStart_ = 0;

    // What was observed, which is the product of this surface.
    uint32_t reconnects_ = 0;
    uint32_t eapolSeen_  = 0;
    uint32_t probesSeen_ = 0;
    uint32_t answered_   = 0;

    dot11::Target pmkidTarget_;
    bool          pmkidSaved_ = false;
    char          pmkidPath_[48] = {0};

    dot11::Sequencer seq_;
    uint8_t          csaCountdown_ = 3;
    uint8_t          csaTarget_    = 0;

    View     view_       = View::Networks;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
