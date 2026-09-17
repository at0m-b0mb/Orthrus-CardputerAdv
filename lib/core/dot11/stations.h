// The devices in a room, and what they give away by looking for Wi-Fi.
//
// A phone that is not connected to anything is not silent. It sends probe
// requests, and in many cases those name the networks it has joined before --
// so a device walking past announces, to anyone listening, where it has been.
// That is the finding, and it needs no association, no key and no interaction
// with the device at all.
//
// TWO THINGS THIS IS CAREFUL ABOUT
//
// Randomised addresses. Modern phones use a locally-administered MAC that
// changes, so counting addresses overcounts devices badly. The table reports
// which addresses are randomised so nobody reads a list of thirty as thirty
// people.
//
// Named probes are rarer than they used to be. Both Android and iOS now send
// mostly broadcast probes with no SSID in them. A device that probes for
// nothing is the normal case, not a failure to capture, and the screen says so.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

#include "dot11/frame.h"

namespace orthrus::dot11 {

// How many named networks to remember per device. Four is enough to make the
// point -- a device probing for "BA Lounge" and a home router has already said
// more than its owner intended.
inline constexpr uint8_t kMaxProbesPerStation = 4;

struct Station {
    uint8_t mac[kMacLen] = {0};

    // Bit 1 of the first octet is the locally-administered bit. Every phone
    // doing MAC randomisation sets it, so this separates "one device seen
    // repeatedly" from "one device wearing a new address each time".
    bool randomised = false;

    int8_t   rssi     = 0;
    int8_t   bestRssi = -127;
    uint32_t frames   = 0;
    uint32_t probes   = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs  = 0;

    // Named networks this device has asked for.
    char    ssids[kMaxProbesPerStation][kSsidBuf] = {{0}};
    uint8_t ssidCount = 0;

    // The access point it is talking to, when we have seen it in a data frame.
    uint8_t bssid[kMacLen] = {0};
    bool    associated     = false;

    bool hasNamedProbes() const { return ssidCount > 0; }
};

class StationTable {
public:
    static constexpr uint8_t kMaxStations = 24;

    void clear();

    // A device seen sending anything at all.
    Station* touch(const uint8_t mac[kMacLen], int8_t rssi, uint32_t nowMs);

    // A probe request naming a network. An empty or NULL-padded SSID is a
    // broadcast probe and is counted but not stored -- it names nothing.
    void noteProbe(const uint8_t mac[kMacLen], const char* ssid, int8_t rssi,
                   uint32_t nowMs);

    // A data frame between a device and an access point.
    void noteAssociation(const uint8_t mac[kMacLen], const uint8_t bssid[kMacLen],
                         int8_t rssi, uint32_t nowMs);

    uint8_t        count() const { return count_; }
    const Station& at(uint8_t i) const { return stations_[i]; }

    // How many devices have given up at least one network name.
    uint8_t talkers() const;

    uint32_t dropped() const { return dropped_; }

private:
    int find(const uint8_t mac[kMacLen]) const;
    // Evicts the device heard longest ago, so the list describes the room the
    // operator is standing in now.
    int evictOldest();

    Station  stations_[kMaxStations];
    uint8_t  count_   = 0;
    uint32_t dropped_ = 0;
};

// True when a MAC carries the locally-administered bit.
bool macIsRandomised(const uint8_t mac[kMacLen]);

}  // namespace orthrus::dot11
