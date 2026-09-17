// Engagement: the session, its evidence log, and getting it off the device.
//
// Everything the other surfaces find lands in one append-only file with a
// running hash chain. This screen shows the state of that file, puts the head
// digest where an operator can photograph it, and writes the geotagged export.

#pragma once

#include <cstdint>

#include "hal/gnss.h"

namespace orthrus::modules {

class SysEvidence {
public:
    bool begin();
    void run();

private:
    void draw();
    void drawResult();
    bool handleKeys();

    // Re-reads the session CSV and writes a KML beside it. Re-reading rather
    // than keeping a second copy in memory is deliberate: the log is the single
    // source of truth, so the map cannot drift from the evidence.
    void exportKml();

    hal::Gnss& gnss_ = hal::sharedGnss();

    enum class View : uint8_t { Status, Result };
    View view_ = View::Status;

    char     resultTitle_[32] = {0};
    char     resultBody_[96]  = {0};
    bool     resultOk_        = false;
    uint32_t lastDrawMs_      = 0;
};

}  // namespace orthrus::modules
