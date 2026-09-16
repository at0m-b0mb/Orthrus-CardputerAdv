// Regional channel plans.
//
// Pure data, kept out of the radio driver so the coverage arithmetic that
// drives every absence-based finding can be tested on the host. The numbers
// here are what make "we heard 1 of 48" true rather than a slogan -- and in
// US915 it is 1 of 512, which is worth seeing written down.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::lorawan {

enum class Region : uint8_t {
    EU868 = 0,
    US915,
    AU915,
    AS923,
};

struct ChannelPlan {
    Region          region;
    const char*     name;
    const uint32_t* uplinkHz;
    uint8_t         uplinkCount;
    uint8_t         sfMin;         // inclusive
    uint8_t         sfMax;         // inclusive
    uint16_t        defaultBwKhz;
    bool            legalToTransmit;  // duty-cycle / LBT regimes differ wildly

    uint8_t sfCount() const {
        return static_cast<uint8_t>(sfMax >= sfMin ? sfMax - sfMin + 1 : 0);
    }

    // Total channel x SF combinations a gateway covers and one radio does not.
    uint16_t combinations() const {
        return static_cast<uint16_t>(uplinkCount) * static_cast<uint16_t>(sfCount());
    }
};

const ChannelPlan& plan(Region r);
const char*        regionName(Region r);
size_t             regionCount();
Region             regionAt(size_t i);

// How many channels of this region we actually hold a frequency table for.
// Distinct from ChannelPlan::uplinkCount, which describes the real band: US915
// has 64 uplink channels but a handheld sweeps a window of them, and the
// coverage figure must be computed against the band, not the window.
uint8_t sweepableChannels(Region r);

}  // namespace orthrus::lorawan
