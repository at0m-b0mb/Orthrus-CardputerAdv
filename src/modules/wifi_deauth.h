// Deauth: can clients on this network be forced off?
//
// WHY THIS EXISTS, AND WHY IT IS SHAPED LIKE AN ASSESSMENT
//
// 802.11 management frames are unauthenticated unless a network turns on
// Protected Management Frames (802.11w). Where it is off, anyone in range can
// forge a disconnect for any client, and the whole network is one cheap radio
// away from being unusable. That is a real finding, clients are routinely asked
// to have it tested, and testing it means sending the frame.
//
// So the product of this surface is NOT "we knocked people off". It is an
// answer to a question:
//
//   1. Read the target's beacon and report whether 802.11w is off, optional or
//      required -- BEFORE transmitting anything. On a network that requires it,
//      the honest result is available without a single frame being sent.
//   2. If the operator chooses to run the test anyway, send a bounded burst at
//      ONE network they picked by hand.
//   3. Then listen, and report what actually happened: clients reconnecting is
//      proof the forgery worked. Silence is not proof it did not.
//
// WHAT IT WILL NOT DO, AND WHY
//
// One target, selected by hand. There is no "all networks" mode, because that
// is not a test of anything -- it is interference with the neighbours, who did
// not agree to it and whose equipment is not in anyone's scope. The burst is
// bounded to kMaxBurstMs and stops on its own; nothing here runs until the
// battery dies.
//
// A note on the common argument that a board this small cannot really disrupt
// anything: it is wrong. Deauthentication is cheap, and one ESP32 can hold a
// floor of clients off a network indefinitely. The bound below exists because
// the hardware is capable, not because it is not.

#pragma once

#include <cstdint>

#include "dot11/frame.h"
#include "hal/gnss.h"

namespace orthrus::modules {

class WifiDeauth {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Target, Firing, Watching, Result };

    static constexpr uint8_t  kMaxNetworks = 24;
    // Long enough to be conclusive, short enough that a forgotten device is not
    // still transmitting five minutes later.
    static constexpr uint32_t kMaxBurstMs  = 20000;
    // How long to listen afterwards for clients coming back.
    static constexpr uint32_t kWatchMs     = 12000;

    struct Network {
        char    ssid[dot11::kSsidBuf] = {0};
        uint8_t bssid[dot11::kMacLen] = {0};
        uint8_t channel = 0;
        int8_t  rssi    = 0;

        bool          haveBeacon = false;   // we read its RSN element ourselves
        dot11::RsnInfo rsn;
        bool          hasWps = false;
        bool          open   = false;       // no RSN and no WPA element at all
    };

    // What 802.11w means for this test, decided before anything is sent.
    enum class Protection : uint8_t { Unknown = 0, Off, Optional, Required, OpenNetwork };

    void startScan();
    void collectScan();
    void readTargetBeacon();     // park on the channel and parse its RSN
    void stepBurst();
    void stepWatch();
    void finish();

    Protection protectionOf(const Network& n) const;
    static const char* protectionName(Protection p);

    void drawList();
    void drawTarget();
    void drawFiring();
    void drawWatching();
    void drawResult();
    bool handleKeys();

    hal::Gnss& gnss_ = hal::sharedGnss();

    Network nets_[kMaxNetworks];
    uint8_t count_    = 0;
    int     selected_ = 0;
    int     scroll_   = 0;

    bool     scanning_    = false;
    uint32_t scanStarted_ = 0;

    bool     armed_      = false;
    uint32_t burstStart_ = 0;
    uint32_t framesSent_ = 0;
    uint32_t watchStart_ = 0;

    // Evidence that the forgery worked: clients reassociating afterwards.
    uint32_t reconnects_   = 0;
    uint32_t eapolSeen_    = 0;
    uint32_t deauthEchoed_ = 0;

    View     view_       = View::List;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
