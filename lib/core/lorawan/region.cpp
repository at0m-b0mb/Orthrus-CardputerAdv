#include "region.h"

namespace orthrus::lorawan {
namespace {

// EU868: the six mandatory join channels plus the two most commonly configured.
constexpr uint32_t kEu868[] = {
    868100000, 868300000, 868500000,
    867100000, 867300000, 867500000, 867700000, 867900000,
};

// US915 uplink channels are 902.3 MHz + 200 kHz * n, n = 0..63, at 125 kHz.
// Listing the first sixteen keeps the table honest about what a handheld can
// realistically sweep; the combination count below still uses the true 64 so
// the coverage figure does not flatter us.
constexpr uint32_t kUs915[] = {
    902300000, 902500000, 902700000, 902900000,
    903100000, 903300000, 903500000, 903700000,
    903900000, 904100000, 904300000, 904500000,
    904700000, 904900000, 905100000, 905300000,
};

constexpr uint32_t kAu915[] = {
    915200000, 915400000, 915600000, 915800000,
    916000000, 916200000, 916400000, 916600000,
};

constexpr uint32_t kAs923[] = {
    923200000, 923400000, 923600000, 923800000,
    924000000, 924200000, 924400000, 924600000,
};

constexpr ChannelPlan kPlans[] = {
    {Region::EU868, "EU868", kEu868, 8,  7, 12, 125, true},
    // US915's real uplink space is 64 channels; we sweep a window of it.
    {Region::US915, "US915", kUs915, 64, 7, 10, 125, true},
    {Region::AU915, "AU915", kAu915, 64, 7, 12, 125, true},
    {Region::AS923, "AS923", kAs923, 8,  7, 12, 125, true},
};

// The tables above are shorter than `uplinkCount` for the 64-channel regions,
// deliberately: count describes the band, the array describes what we sweep.
constexpr uint8_t kSweepable[] = {8, 16, 8, 8};

}  // namespace

const ChannelPlan& plan(Region r) {
    const size_t i = static_cast<size_t>(r);
    return kPlans[i < regionCount() ? i : 0];
}

const char* regionName(Region r) { return plan(r).name; }

size_t regionCount() { return sizeof(kPlans) / sizeof(kPlans[0]); }

Region regionAt(size_t i) {
    return kPlans[i < regionCount() ? i : 0].region;
}

uint8_t sweepableChannels(Region r) {
    const size_t i = static_cast<size_t>(r);
    return kSweepable[i < regionCount() ? i : 0];
}

}  // namespace orthrus::lorawan
