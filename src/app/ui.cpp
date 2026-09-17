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

namespace {

M5Canvas g_canvas(&M5Cardputer.Display);
bool     g_haveCanvas = false;
bool     g_attempted  = false;

}  // namespace

LovyanGFX& gfx() {
    return g_haveCanvas ? static_cast<LovyanGFX&>(g_canvas)
                        : static_cast<LovyanGFX&>(M5Cardputer.Display);
}

bool beginFrame() {
    if (!g_attempted) {
        g_attempted = true;
        g_canvas.setColorDepth(16);
        // 240 x 135 x 16bpp is ~65 KB against ~359 KB of heap. Affordable, but
        // checked rather than assumed: there is no PSRAM to fall back on.
        g_haveCanvas = (g_canvas.createSprite(bd::kScreenW, bd::kScreenH) != nullptr);
    }
    gfx().fillScreen(kInk);
    return g_haveCanvas;
}

void endFrame() {
    if (g_haveCanvas) g_canvas.pushSprite(0, 0);
}

void chrome(const char* title, const char* right) {
    auto& d = gfx();

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
    auto& d = gfx();
    const int top = bd::kScreenH - kFooterH;

    d.drawFastHLine(0, top, bd::kScreenW, kRule);
    d.setFont(kFaceData);
    d.setTextDatum(middle_left);
    d.setTextColor(kFaint, kInk);
    d.drawString(hint, kPad + 2, top + kFooterH / 2 + 1);
    d.setTextDatum(top_left);
}

void listRow(int y, int height, bool selected) {
    if (!selected) return;
    auto& d = gfx();
    d.fillRect(0, y, bd::kScreenW, height, kSurface);
    // A gold edge rather than a gold fill: bright gold cannot carry text, so it
    // marks the row from the side instead.
    d.fillRect(0, y, 2, height, kShine);
}

void detailStrip(int y, const char* text) {
    auto& d = gfx();
    d.drawFastHLine(0, y, bd::kScreenW, kRule);
    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString(text, kPad + 2, y + 5);
}

int coverageGrid(int x, int y, uint8_t cols, uint8_t rows, int litCol, int litRow,
                 int maxWidth) {
    auto& d = gfx();
    if (cols == 0 || rows == 0) return y;

    constexpr int kGap = 1;
    int cell = (maxWidth - (cols - 1) * kGap) / cols;
    if (cell > 4) cell = 4;
    if (cell < 2) cell = 2;

    for (int c = 0; c < cols; c++) {
        for (int r = 0; r < rows; r++) {
            const int cx = x + c * (cell + kGap);
            const int cy = y + r * (cell + kGap);
            if (c == litCol && r == litRow) {
                d.fillRect(cx, cy, cell, cell, kShine);
            } else {
                // Unheard cells are drawn, never omitted. The whole point is
                // that they exist and we are deaf to them.
                d.drawRect(cx, cy, cell, cell, kRule);
            }
        }
    }
    return y + rows * (cell + kGap);
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

uint16_t severityColour(credential::Severity s) {
    switch (s) {
        case credential::Severity::Critical: return kCritical;
        case credential::Severity::High:     return kHigh;
        case credential::Severity::Medium:   return kMedium;
        case credential::Severity::Low:      return kLow;
        case credential::Severity::Info:     return kInfo;
    }
    return kMuted;
}

uint16_t gradeColour(credential::Grade g) {
    switch (g) {
        case credential::Grade::APlus:
        case credential::Grade::A:     return kGood;
        case credential::Grade::B:     return kLow;
        case credential::Grade::C:     return kMedium;
        case credential::Grade::D:     return kHigh;
        case credential::Grade::F:     return kCritical;
    }
    return kMuted;
}

uint16_t severityColour(wifi::Severity s) {
    switch (s) {
        case wifi::Severity::Critical: return kCritical;
        case wifi::Severity::High:     return kHigh;
        case wifi::Severity::Medium:   return kMedium;
        case wifi::Severity::Low:      return kLow;
        case wifi::Severity::Info:     return kInfo;
    }
    return kMuted;
}

uint16_t gradeColour(wifi::Grade g) {
    switch (g) {
        case wifi::Grade::APlus:
        case wifi::Grade::A:     return kGood;
        case wifi::Grade::B:     return kLow;
        case wifi::Grade::C:     return kMedium;
        case wifi::Grade::D:     return kHigh;
        case wifi::Grade::F:     return kCritical;
    }
    return kMuted;
}

void textAt(int x, int y, uint16_t colour, const char* fmt, ...) {
    char buf[72];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    auto& d = gfx();
    d.setTextDatum(middle_left);
    d.setTextColor(colour, kInk);
    d.drawString(buf, x, y);
    d.setTextDatum(top_left);
}

void textRight(int rightEdge, int y, uint16_t colour, const char* fmt, ...) {
    char buf[72];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    auto& d = gfx();
    d.setTextDatum(middle_right);
    d.setTextColor(colour, kInk);
    d.drawString(buf, rightEdge, y);
    d.setTextDatum(top_left);
}

int wrapText(int x, int y, int maxWidth, int lineHeight, int maxLines,
             uint16_t colour, const char* text) {
    auto& d = gfx();
    d.setTextDatum(top_left);
    d.setTextColor(colour, kInk);

    char   line[64] = {0};
    size_t lineLen = 0;
    int    drawn   = 0;

    const char* word = text;
    while (drawn < maxLines) {
        const char* end = word;
        while (*end && *end != ' ') end++;
        const size_t wordLen = static_cast<size_t>(end - word);
        if (wordLen == 0 && *end == '\0') break;

        // Measure the candidate rather than assuming a characters-per-line
        // constant, which is wrong the moment the face changes.
        char         candidate[64];
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

}  // namespace orthrus::ui
