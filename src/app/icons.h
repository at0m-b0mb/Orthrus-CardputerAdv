// Category glyphs.
//
// Drawn as vectors rather than shipped as bitmaps. A 16 px bitmap set for nine
// categories is about 300 bytes of flash and zero flexibility; these cost
// nothing at rest, scale with the theme, and can knock a hole through whatever
// the tile behind them happens to be filled with.
//
// Every glyph is centred on (cx, cy) and stays inside a 16 x 16 box, so the
// grid can lay them out on a fixed rhythm without measuring anything.
//
// House style, not decoration: one colour, hairline weight, no gradients, no
// emoji. Emoji would render as a missing glyph in these faces anyway, and a
// row of tofu boxes is exactly the look this product is avoiding.

#pragma once

#include <cstdint>

namespace orthrus::icons {

inline constexpr int kBox = 16;

enum class Glyph : uint8_t {
    Wifi = 0,
    Bluetooth,
    Nfc,
    Rfid,
    Infrared,
    Lora,
    Gps,
    Usb,
    System,
};

// `background` is the colour behind the glyph, used by the few marks that are
// knocked out rather than drawn -- the hole in the map pin, for instance. It
// has to be passed in because a selected tile is filled and an unselected one
// is not.
void draw(Glyph g, int cx, int cy, uint16_t colour, uint16_t background);

}  // namespace orthrus::icons
