#include "spectrum.h"

#include <M5Cardputer.h>

#include "app/theme.h"
#include "app/ui.h"

namespace orthrus::modules {

using namespace orthrus::theme;

namespace {

int8_t clampDbm(float v) {
    if (v < Spectrum::kFloorDbm) return Spectrum::kFloorDbm;
    if (v > Spectrum::kCeilingDbm) return Spectrum::kCeilingDbm;
    return static_cast<int8_t>(v);
}

}  // namespace

void Spectrum::configure(uint32_t fromHz, uint32_t toHz) {
    if (toHz <= fromHz) return;
    if (startHz_ == fromHz && endHz_ == toHz) return;
    startHz_ = fromHz;
    endHz_   = toHz;
    reset();
}

void Spectrum::reset() {
    for (int i = 0; i < kBins; i++) {
        bins_[i] = kFloorDbm;
        hold_[i] = kFloorDbm;
    }
    cursor_ = 0;
    sweeps_ = 0;
}

uint32_t Spectrum::binFreqHz(int bin) const {
    if (bin < 0) bin = 0;
    if (bin >= kBins) bin = kBins - 1;
    const uint64_t span = static_cast<uint64_t>(endHz_ - startHz_);
    return startHz_ + static_cast<uint32_t>((span * static_cast<uint64_t>(bin)) /
                                            static_cast<uint64_t>(kBins - 1));
}

bool Spectrum::step(hal::LoraRadio& radio, int points) {
    bool wrapped = false;

    for (int i = 0; i < points; i++) {
        const float v = radio.sampleFloorAt(binFreqHz(cursor_));
        if (v != 0.0f) {
            const int8_t sample = clampDbm(v);
            bins_[cursor_] = sample;
            // Max-hold is what makes a bursty transmitter visible at all: a
            // LoRa uplink is on air for well under a second and a live trace
            // will almost always miss it.
            if (sample > hold_[cursor_]) hold_[cursor_] = sample;
        }

        cursor_++;
        if (cursor_ >= kBins) {
            cursor_ = 0;
            sweeps_++;
            wrapped = true;
        }
    }
    return wrapped;
}

int Spectrum::peakBin() const {
    int best = 0;
    for (int i = 1; i < kBins; i++) {
        if (hold_[i] > hold_[best]) best = i;
    }
    return best;
}

void Spectrum::draw(int x, int y, int w, int h) const {
    auto& d = ui::gfx();

    const int span = kCeilingDbm - kFloorDbm;  // 68 dB
    const int barW = w / kBins;
    const int usedW = barW * kBins;

    // A faint reference line at -100 dBm gives the eye something to judge
    // height against; without it every trace looks equally tall.
    const int refY = y + h - ((-100 - kFloorDbm) * h) / span;
    d.drawFastHLine(x, refY, usedW, kRule);

    for (int i = 0; i < kBins; i++) {
        const int bx = x + i * barW;

        const int lvl = bins_[i];
        int barH = ((lvl - kFloorDbm) * h) / span;
        if (barH < 0) barH = 0;
        if (barH > h) barH = h;

        const int hld = hold_[i];
        int holdH = ((hld - kFloorDbm) * h) / span;
        if (holdH < 0) holdH = 0;
        if (holdH > h) holdH = h;

        // Live trace in brass, max-hold as a bright cap above it. Two golds
        // doing the job one cannot: the fill carries no text, the cap marks.
        if (barH > 0) d.fillRect(bx, y + h - barH, barW, barH, kBrass);
        if (holdH > barH) d.fillRect(bx, y + h - holdH, barW, 1, kShine);

        // The bin currently being measured, so the sweep is visibly alive.
        if (i == cursor_) d.drawFastVLine(bx, y, h, kMuted);
    }

    d.drawFastHLine(x, y + h, usedW, kRule);
}

}  // namespace orthrus::modules
