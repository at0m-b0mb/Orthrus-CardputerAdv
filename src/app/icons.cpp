#include "icons.h"

#include "ui.h"

namespace orthrus::icons {

namespace {

// M5GFX arc angles: 0 is at 3 o'clock and they increase clockwise, because the
// y axis points down. So 270 is straight up, and a fan opening upwards runs
// 225 to 315. Written down because getting it wrong silently draws the arc on
// the opposite side, which looks like the glyph simply failed to appear.
constexpr float kUp    = 270.0f;
constexpr float kRight = 0.0f;

void wifi(int cx, int cy, uint16_t c) {
    // Three arcs rising from a single point, the way a beacon actually reads.
    const int bx = cx;
    const int by = cy + 7;
    auto& d = ui::gfx();
    d.fillCircle(bx, by, 1, c);
    d.drawArc(bx, by, 4, 5, kUp - 42, kUp + 42, c);
    d.drawArc(bx, by, 8, 9, kUp - 42, kUp + 42, c);
    d.drawArc(bx, by, 12, 13, kUp - 42, kUp + 42, c);
}

void bluetooth(int cx, int cy, uint16_t c) {
    // The Bjarkan rune: a spine with two diagonals crossing through it. The
    // crossing is what makes it read as Bluetooth rather than as a stray B.
    auto& d = ui::gfx();
    d.drawLine(cx, cy - 8, cx, cy + 8, c);
    d.drawLine(cx, cy - 8, cx + 4, cy - 4, c);
    d.drawLine(cx + 4, cy - 4, cx - 4, cy + 4, c);
    d.drawLine(cx, cy + 8, cx + 4, cy + 4, c);
    d.drawLine(cx + 4, cy + 4, cx - 4, cy - 4, c);
}

void nfc(int cx, int cy, uint16_t c) {
    // A card with its chip, and the field coming off the short edge.
    auto& d = ui::gfx();
    d.drawRoundRect(cx - 8, cy - 6, 9, 12, 2, c);
    d.fillRect(cx - 6, cy - 2, 4, 4, c);
    d.drawArc(cx - 1, cy, 4, 5, kRight - 45, kRight + 45, c);
    d.drawArc(cx - 1, cy, 7, 8, kRight - 45, kRight + 45, c);
}

void rfid(int cx, int cy, uint16_t c) {
    // A keyfob, hole and all, with the antenna coil inside it. Deliberately a
    // different silhouette from the NFC card: the two categories sit next to
    // each other on the grid and must not read as the same icon.
    auto& d = ui::gfx();
    d.drawRoundRect(cx - 6, cy - 8, 12, 16, 3, c);
    d.drawCircle(cx, cy - 4, 2, c);
    d.drawRoundRect(cx - 4, cy + 1, 8, 6, 1, c);
    d.drawFastHLine(cx - 2, cy + 4, 4, c);
}

void infrared(int cx, int cy, uint16_t c) {
    // An emitter and a straight, narrow beam. Wi-Fi radiates; infrared is aimed,
    // and the icon says which is which.
    auto& d = ui::gfx();
    d.fillRect(cx - 8, cy - 4, 3, 9, c);
    d.fillArc(cx - 6, cy, 0, 4, kRight - 90, kRight + 90, c);
    d.drawFastHLine(cx - 1, cy, 3, c);
    d.drawFastHLine(cx + 3, cy, 3, c);
    d.drawFastHLine(cx + 7, cy, 2, c);
    d.drawLine(cx - 1, cy - 3, cx + 8, cy - 6, c);
    d.drawLine(cx - 1, cy + 3, cx + 8, cy + 6, c);
}

void lora(int cx, int cy, uint16_t c) {
    // A mast, transmitting. The arcs stop short of vertical so the whole glyph
    // stays inside the 16 px box instead of clipping against the tile above.
    auto& d = ui::gfx();
    d.drawLine(cx - 4, cy + 8, cx, cy + 1, c);
    d.drawLine(cx + 4, cy + 8, cx, cy + 1, c);
    d.drawFastHLine(cx - 2, cy + 5, 5, c);
    d.fillCircle(cx, cy, 1, c);
    d.drawArc(cx, cy, 3, 4, 200, 250, c);
    d.drawArc(cx, cy, 3, 4, 290, 340, c);
    d.drawArc(cx, cy, 6, 7, 200, 250, c);
    d.drawArc(cx, cy, 6, 7, 290, 340, c);
}

void gps(int cx, int cy, uint16_t c, uint16_t bg) {
    // A pin. The hole is knocked out in the tile's own background rather than
    // drawn in black, so it stays a hole when the tile is selected and filled.
    auto& d = ui::gfx();
    d.fillCircle(cx, cy - 3, 5, c);
    d.fillTriangle(cx - 4, cy + 1, cx + 4, cy + 1, cx, cy + 8, c);
    d.fillCircle(cx, cy - 3, 2, bg);
}

void usb(int cx, int cy, uint16_t c) {
    // The trident, with its two unequal terminals: a square on one branch and a
    // circle on the other. Those are the detail that makes it recognisable at
    // this size.
    auto& d = ui::gfx();
    d.drawLine(cx, cy - 4, cx, cy + 6, c);
    d.fillCircle(cx, cy + 7, 2, c);
    d.fillTriangle(cx - 3, cy - 4, cx + 3, cy - 4, cx, cy - 8, c);
    d.drawLine(cx, cy + 2, cx - 5, cy - 3, c);
    d.fillRect(cx - 7, cy - 5, 4, 4, c);
    d.drawLine(cx, cy - 1, cx + 5, cy - 6, c);
    d.fillCircle(cx + 6, cy - 6, 2, c);
}

void system(int cx, int cy, uint16_t c) {
    // A gauge: the one thing on this device that is purely about the device.
    auto& d = ui::gfx();
    d.drawArc(cx, cy + 4, 7, 8, 180, 360, c);
    d.drawLine(cx, cy + 4, cx - 4, cy - 2, c);
    d.fillCircle(cx, cy + 4, 2, c);
    d.drawFastHLine(cx - 8, cy + 6, 17, c);
}

}  // namespace

void draw(Glyph g, int cx, int cy, uint16_t colour, uint16_t background) {
    switch (g) {
        case Glyph::Wifi:      wifi(cx, cy, colour); break;
        case Glyph::Bluetooth: bluetooth(cx, cy, colour); break;
        case Glyph::Nfc:       nfc(cx, cy, colour); break;
        case Glyph::Rfid:      rfid(cx, cy, colour); break;
        case Glyph::Infrared:  infrared(cx, cy, colour); break;
        case Glyph::Lora:      lora(cx, cy, colour); break;
        case Glyph::Gps:       gps(cx, cy, colour, background); break;
        case Glyph::Usb:       usb(cx, cy, colour); break;
        case Glyph::System:    system(cx, cy, colour); break;
    }
}

}  // namespace orthrus::icons
