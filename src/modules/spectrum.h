// Live spectrum sweep.
//
// Earned its place by being the measurement that proved the radio actually
// retunes: sweeping 863-930 MHz on real hardware gave a floor from -116.9 to
// -103.6 dBm with 13.3 dB of frequency-dependent structure, where a stuck
// synthesiser would have drawn a flat line. A diagnostic that good is also a
// recon tool -- it answers "what is transmitting around here?" before you know
// what protocol to look for.
//
// Swept a few points per frame rather than all at once, so the trace fills in
// while the UI stays responsive instead of freezing for three seconds.

#pragma once

#include <cstdint>

#include "hal/lora_radio.h"

namespace orthrus::modules {

class Spectrum {
public:
    // 116 bins at 2 px each fills the panel width with room for an axis.
    static constexpr int kBins = 116;

    // dBm window the graph maps onto its height. Anything outside is clamped,
    // and the clamp is visible rather than silently folded.
    static constexpr int kFloorDbm   = -128;
    static constexpr int kCeilingDbm = -60;

    void configure(uint32_t startHz, uint32_t endHz);
    void reset();

    // Advances the sweep. Returns true when a full pass has just completed.
    bool step(hal::LoraRadio& radio, int points = 3);

    // Draws the trace, its max-hold, and the frequency axis.
    void draw(int x, int y, int w, int h) const;

    int      peakBin() const;
    uint32_t binFreqHz(int bin) const;
    int8_t   level(int bin) const { return bins_[bin]; }
    int8_t   hold(int bin) const { return hold_[bin]; }
    uint32_t sweeps() const { return sweeps_; }
    int      cursor() const { return cursor_; }
    bool     hasData() const { return sweeps_ > 0 || cursor_ > 0; }

    uint32_t startHz() const { return startHz_; }
    uint32_t endHz() const { return endHz_; }

private:
    uint32_t startHz_ = 863000000;
    uint32_t endHz_   = 870000000;

    int8_t   bins_[kBins] = {0};
    int8_t   hold_[kBins] = {0};
    int      cursor_      = 0;
    uint32_t sweeps_      = 0;
};

}  // namespace orthrus::modules
