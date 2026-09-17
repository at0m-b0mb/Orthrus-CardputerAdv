// Position: the GNSS receiver on the LoRa cap, and what it is worth.
//
// Three states, kept visibly distinct because they need completely different
// responses from the operator and they look identical on a lazy screen:
//
//   nothing      no NMEA at all -- the cap is not seated, or the wrong pins
//   receiving    sentences are parsing, no fix yet -- go outside, or wait
//   fix          a position, with the radius it is actually good to
//
// A device that shows "0.000000, 0.000000" for all three is the reason people
// think GPS modules are broken.
//
// WHY IT MATTERS ON AN ENGAGEMENT
//
// Every finding on this device can carry a position, and a position is what
// turns "we found an open network" into "we found an open network HERE". This
// screen is where the operator marks the points that matter -- the reader by
// the door, the antenna on the roof -- straight into the evidence chain, so
// they come out in the KML export with everything else.

#pragma once

#include <cstdint>

#include "hal/gnss.h"

namespace orthrus::modules {

class Position {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { Live, Waypoints, Marked };

    static constexpr uint8_t kMaxWaypoints = 12;

    struct Waypoint {
        double   lat = 0, lon = 0;
        uint16_t errorM = 0;
        uint32_t atMs = 0;
        uint8_t  satellites = 0;
    };

    void pump();
    bool mark();

    void drawLive();
    void drawWaypoints();
    void drawMarked();
    bool handleKeys();

    void skyMeter(int x, int y, int w, uint32_t satellites);

    hal::Gnss& gnss_ = hal::sharedGnss();

    Waypoint waypoints_[kMaxWaypoints];
    uint8_t  waypointCount_ = 0;
    int      selected_      = 0;

    // Set when the operator asked to mark a point but there was nothing worth
    // marking. Refusing loudly beats writing a pin nobody can trust.
    const char* markError_ = nullptr;

    bool     tracking_     = false;
    uint32_t lastTrackMs_  = 0;
    uint32_t trackPoints_  = 0;

    View     view_        = View::Live;
    uint32_t lastDrawMs_  = 0;
    uint32_t enteredMs_   = 0;
};

}  // namespace orthrus::modules
