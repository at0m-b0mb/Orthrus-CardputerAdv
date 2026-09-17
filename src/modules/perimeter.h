// Perimeter: the Wi-Fi surface.
//
// A passive scan, graded, geotagged and logged. Every access point seen goes
// into the same evidence chain as everything else, so a walk around a site
// produces one file and one map.
//
// Receive-only. There is no deauthentication, no beacon flooding and no
// jamming here, and there will not be: that is denial of service rather than
// assessment, it is the single feature that gets devices like this pulled from
// sale, and none of it is needed to tell a client their guest network is open.

#pragma once

#include <cstdint>

#include "hal/gnss.h"
#include "wifi/network.h"

namespace orthrus::modules {

class Perimeter {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Dossier };

    void pump();
    void harvest();
    void drawList();
    void drawDossier();
    bool handleKeys();
    void logNetwork(const wifi::Network& n);

    uint8_t duplicatesOf(const wifi::Network& n) const;
    int     findByBssid(const uint8_t bssid[wifi::kBssidLen]) const;

    // 48 networks is more than a dense office floor shows at once, and the
    // whole table is about 4 KB.
    static constexpr uint8_t kMaxNetworks = 48;

    wifi::Network nets_[kMaxNetworks];
    uint8_t       count_ = 0;

    hal::Gnss& gnss_ = hal::sharedGnss();

    View     view_        = View::List;
    int      selected_    = 0;
    int      scroll_      = 0;
    bool     scanning_    = false;
    uint32_t scanStarted_ = 0;
    uint32_t sweeps_      = 0;
    uint32_t lastDrawMs_  = 0;
    uint32_t newThisScan_ = 0;
};

}  // namespace orthrus::modules
