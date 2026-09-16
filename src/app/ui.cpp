#include "ui.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "hal/board.h"

namespace orthrus::ui {

using namespace orthrus::theme;
namespace bd = orthrus::board;

// Everything is positioned with an explicit datum rather than setCursor.
//
// M5GFX places free-font text on a BASELINE when you use setCursor, so a row
// drawn at y and a highlight drawn at y do not line up -- the text sits low and
// the band appears to float between rows. Datums remove the guesswork: ask for
// middle_left at the row's centre line and the glyphs land where the rectangle
// is. This was a real defect on hardware, not a theoretical one.

void chrome(const char* title, const char* right) {
    auto& d = M5Cardputer.Display;

    d.fillRect(0, 0, bd::kScreenW, kHeaderH, kInk);

    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_left);
    d.setTextColor(kText, kInk);
    d.drawString(title, kPad + 2, kHeaderH / 2);

    if (right != nullptr) {
        d.setFont(kFaceData);
        d.setTextDatum(middle_right);
        d.setTextColor(kBrass, kInk);
        d.drawString(right, bd::kScreenW - kPad - 2, kHeaderH / 2);
    }

    // The single gold rule. It is the only ornament in the product, so it does
    // the work of making the header feel deliberate.
    d.drawFastHLine(0, kHeaderH, bd::kScreenW, kBrass);

    d.setTextDatum(top_left);
}

void footer(const char* hint) {
    auto& d = M5Cardputer.Display;
    const int top = bd::kScreenH - kFooterH;

    d.fillRect(0, top, bd::kScreenW, kFooterH, kInk);
    d.drawFastHLine(0, top, bd::kScreenW, kRule);

    d.setFont(kFaceData);
    d.setTextDatum(middle_left);
    d.setTextColor(kFaint, kInk);
    d.drawString(hint, kPad + 2, top + kFooterH / 2 + 1);
    d.setTextDatum(top_left);
}

void listRow(int y, int height, bool selected) {
    auto& d = M5Cardputer.Display;
    if (!selected) return;

    d.fillRect(0, y, bd::kScreenW, height, kSurface);
    // A gold edge rather than a gold fill: bright gold cannot carry text, so it
    // marks the row from the side instead.
    d.fillRect(0, y, 2, height, kShine);
}

void detailStrip(int y, const char* text) {
    auto& d = M5Cardputer.Display;
    d.drawFastHLine(0, y, bd::kScreenW, kRule);
    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString(text, kPad + 2, y + 5);
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
            if (ch == litChannel && sf == litSf) {
                d.fillRect(cx, cy, kCell, kCell, kShine);
            } else {
                // Unheard cells are drawn, never omitted. The whole point is
                // that they exist and we are deaf to them.
                d.drawRect(cx, cy, kCell, kCell, kRule);
            }
        }
    }
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

void textAt(int x, int y, uint16_t colour, const char* fmt, ...) {
    char buf[72];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    auto& d = M5Cardputer.Display;
    d.setTextDatum(middle_left);
    d.setTextColor(colour, kInk);
    d.drawString(buf, x, y);
    d.setTextDatum(top_left);
}

int wrapText(int x, int y, int maxWidth, int lineHeight, int maxLines,
             uint16_t colour, const char* text) {
    auto& d = M5Cardputer.Display;
    d.setTextDatum(top_left);
    d.setTextColor(colour, kInk);

    char line[64];
    size_t lineLen = 0;
    int    drawn   = 0;

    const char* word = text;
    while (drawn < maxLines) {
        // Take the next word, including the space that follows it.
        const char* end = word;
        while (*end && *end != ' ') end++;
        const size_t wordLen = static_cast<size_t>(end - word);
        if (wordLen == 0 && *end == '\0') break;

        // Would it still fit? Measure the candidate rather than guessing a
        // characters-per-line constant, which is wrong the moment the face
        // changes.
        char candidate[64];
        const size_t sep = (lineLen > 0) ? 1u : 0u;
        if (lineLen + sep + wordLen >= sizeof(candidate)) break;

        std::memcpy(candidate, line, lineLen);
        if (sep) candidate[lineLen] = ' ';
        std::memcpy(candidate + lineLen + sep, word, wordLen);
        candidate[lineLen + sep + wordLen] = '\0';

        if (static_cast<int>(d.textWidth(candidate)) <= maxWidth || lineLen == 0) {
            std::memcpy(line, candidate, lineLen + sep + wordLen + 1);
            lineLen = lineLen + sep + wordLen;
        } else {
            line[lineLen] = '\0';
            d.drawString(line, x, y + drawn * lineHeight);
            drawn++;
            lineLen = 0;
            continue;  // retry this word on the fresh line
        }

        if (*end == '\0') break;
        word = end + 1;
    }

    if (lineLen > 0 && drawn < maxLines) {
        line[lineLen] = '\0';
        d.drawString(line, x, y + drawn * lineHeight);
        drawn++;
    }
    return y + drawn * lineHeight;
}

void textRight(int rightEdge, int y, uint16_t colour, const char* fmt, ...) {
    char buf[72];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    auto& d = M5Cardputer.Display;
    d.setTextDatum(middle_right);
    d.setTextColor(colour, kInk);
    d.drawString(buf, rightEdge, y);
    d.setTextDatum(top_left);
}

}  // namespace orthrus::ui
