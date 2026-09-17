// Clients: the devices in the room, and the networks they are looking for.
//
// A phone that is not connected to anything is not silent. It sends probe
// requests, and some of those name networks it has joined before -- so a device
// walking past can announce, to anyone listening, where it has been. No
// association, no key, no interaction with the device at all.
//
// On an engagement this answers two questions a network scan cannot:
//
//   Who is actually here?    A list of access points says nothing about
//                            whether anybody is using them.
//   What would they join?    A device probing for a named network will
//                            associate with anything answering to that name.
//
// Entirely passive. Nothing is transmitted.
//
// TWO HONESTY PROBLEMS, HANDLED RATHER THAN IGNORED
//
// Randomised addresses: modern phones change their MAC, so a count of
// addresses badly overcounts people. Every row says whether its address is a
// real burned-in one or a randomised one, and the header counts them
// separately.
//
// Named probes are rarer than they were. Both Android and iOS now send mostly
// broadcast probes with no name in them. A device probing for nothing is the
// normal case, not a failed capture, and the screen says so rather than looking
// broken.

#pragma once

#include <cstdint>

#include "dot11/stations.h"

namespace orthrus::modules {

class WifiClients {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Detail };

    void pump();
    void drain();
    void hop();

    void drawList();
    void drawDetail();
    bool handleKeys();

    // ~4 KB. Static storage via the single module instance in main.
    dot11::StationTable table_;

    uint8_t  channel_   = 1;
    bool     locked_    = false;
    uint32_t lastHopMs_ = 0;

    uint32_t probesSeen_ = 0;
    uint32_t namedSeen_  = 0;

    bool talkersOnly_ = false;

    int  selected_ = 0;
    int  scroll_   = 0;
    View view_     = View::List;

    uint32_t lastDrawMs_ = 0;
    uint32_t enteredMs_  = 0;

    int visibleCount() const;
    int visibleAt(int i) const;
};

}  // namespace orthrus::modules
