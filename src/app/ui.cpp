#include "ui.h"

#include <cstdarg>
#include <cstdio>

#include "hal/board.h"

namespace orthrus::ui {

using namespace orthrus::theme;
namespace bd = orthrus::board;

void chrome(const char* title, const char* right) {
    auto& d = M5Cardputer.Display;

    d.fillRect(0, 0, bd::kScreenW, kHeaderH, kInk);
    d.setFont(kFaceIdentity);
    d.setTextColor(kText, kInk);
    d.setCursor(kPad, 2);
    d.print(title);

    if (right != nullptr) {
        d.setFont(kFaceData);
        d.setTextColor(kBrass, kInk);
        const int w = static_cast<int>(d.textWidth(right));
        d.setCursor(bd::kScreenW - kPad - w, 5);
        d.print(right);
    }

    d.drawFastHLine(0, kHeaderH - 1, bd::kScreenW, kRule);
}

void footer(const char* hint) {
    auto& d = M5Cardputer.Display;
    const int y = bd::kScreenH - kFooterH;

    d.fillRect(0, y, bd::kScreenW, kFooterH, kInk);
    d.drawFastHLine(0, y, bd::kScreenW, kRule);
    d.setFont(kFaceData);
    d.setTextColor(kFaint, kInk);
    d.setCursor(kPad, y + 3);
    d.print(hint);
}

void coverageGrid(int x, int y, uint8_t channels, uint8_t sfs,
                  int litChannel, int litSf) {
    auto& d = M5Cardputer.Display;

    constexpr int kCell = 4;
    constexpr int kGap  = 1;

    for (int ch = 0; ch < channels; ch++) {
        for (int sf = 0; sf < sfs; sf++) {
            const int cx = x + ch * (kCell + kGap);
            const int cy = y + sf * (kCell + kGap);
            const bool lit = (ch == litChannel && sf == litSf);
            if (lit) {
                d.fillRect(cx, cy, kCell, kCell, kShine);
            } else {
                // Unheard cells are drawn, not omitted. The point is that they
                // exist and we are deaf to them.
                d.drawRect(cx, cy, kCell, kCell, kRule);
            }
        }
    }

    const int total = static_cast<int>(channels) * static_cast<int>(sfs);
    char buf[24];
    std::snprintf(buf, sizeof(buf), "1 of %d", total);
    d.setFont(kFaceData);
    d.setTextColor(kMuted, kInk);
    d.setCursor(x, y + sfs * (kCell + kGap) + 2);
    d.print(buf);
}

uint16_t severityColour(lorawan::Severity s) {
    switch (s) {
        case lorawan::Severity::Critical: return kCritical;
        case lorawan::Severity::High:     return kHigh;
        case lorawan::Severity::Medium:   return kMedium;
        case lorawan::Severity::Low:      return kLow;
        case lorawan::Severity::Info:     return kInfo;
    }
    return kMuted;
}

uint16_t gradeColour(lorawan::Grade g) {
    switch (g) {
        case lorawan::Grade::APlus:
        case lorawan::Grade::A:     return kGood;
        case lorawan::Grade::B:     return kLow;
        case lorawan::Grade::C:     return kMedium;
        case lorawan::Grade::D:     return kHigh;
        case lorawan::Grade::F:     return kCritical;
    }
    return kMuted;
}

void textRight(int rightEdge, int y, uint16_t colour, const char* fmt, ...) {
    char buf[64];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    auto& d = M5Cardputer.Display;
    d.setTextColor(colour, kInk);
    const int w = static_cast<int>(d.textWidth(buf));
    d.setCursor(rightEdge - w, y);
    d.print(buf);
}

}  // namespace orthrus::ui
