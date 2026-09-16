// Orthrus -- multi-surface red team platform for the M5Stack Cardputer-Adv.
//
// Authorized testing only. The engagement record is not decoration: it is what
// makes a capture a client deliverable rather than an anecdote.

#include <M5Cardputer.h>

#include <cstdio>

#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"
#include "modules/airspace.h"

using namespace orthrus::theme;
namespace bd = orthrus::board;

namespace {

constexpr char kVersion[] = "0.1.0";

constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';

// Vertical layout for a 135 px panel, written down rather than scattered.
//
// The first build put five two-line rows here and the last one fell off the
// bottom behind the footer. One line per row, with the description shown once
// for the selected item, is what actually fits -- and it reads better.
constexpr int kListTop    = 21;
constexpr int kRowH       = 15;
constexpr int kDetailRule = 99;
constexpr int kDetailText = 104;

struct Surface {
    const char* name;
    const char* blurb;
    bool        ready;
};

// Product vocabulary, not framework vocabulary. Each name is what the operator
// is actually pointing the device at.
const Surface kSurfaces[] = {
    {"Airspace",    "LoRa and LoRaWAN device census",  true},
    {"Perimeter",   "Wi-Fi recon and captive portals", false},
    {"Credentials", "NFC and 125 kHz badge work",      false},
    {"Control",     "Infrared and USB payloads",       false},
    {"Engagement",  "Scope, evidence log, export",     false},
};
constexpr int kSurfaceCount = sizeof(kSurfaces) / sizeof(kSurfaces[0]);

int g_selected = 0;

void drawSplash() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_center);
    d.setTextColor(kText, kInk);
    d.drawString("ORTHRUS", bd::kScreenW / 2, 44);

    // One gold rule, centred under the wordmark.
    d.drawFastHLine(bd::kScreenW / 2 - 52, 58, 104, kShine);

    d.setFont(kFaceData);
    d.setTextColor(kBrass, kInk);
    d.drawString("multi-surface red team platform", bd::kScreenW / 2, 72);

    d.setTextColor(kFaint, kInk);
    d.drawString("authorized testing only", bd::kScreenW / 2, 86);

    char ver[24];
    std::snprintf(ver, sizeof(ver), "v%s", kVersion);
    d.setTextColor(kFaint, kInk);
    d.drawString(ver, bd::kScreenW / 2, 104);

    d.setTextDatum(top_left);
}

void drawMenu() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    char batt[12];
    std::snprintf(batt, sizeof(batt), "%d%%", M5.Power.getBatteryLevel());
    orthrus::ui::chrome("Surfaces", batt);

    for (int i = 0; i < kSurfaceCount; i++) {
        const int y   = kListTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (i == g_selected);

        orthrus::ui::listRow(y, kRowH, sel);

        d.setFont(kFaceUi);
        d.setTextDatum(middle_left);
        d.setTextColor(kSurfaces[i].ready ? kText : kFaint, sel ? kSurface : kInk);
        d.drawString(kSurfaces[i].name, 10, mid);

        if (!kSurfaces[i].ready) {
            d.setFont(kFaceData);
            d.setTextDatum(middle_right);
            d.setTextColor(kFaint, sel ? kSurface : kInk);
            d.drawString("soon", bd::kScreenW - 6, mid);
        }
    }

    orthrus::ui::detailStrip(kDetailRule, kSurfaces[g_selected].blurb);
    orthrus::ui::footer("; . move    enter open");
    d.setTextDatum(top_left);
}

// Shared "press anything to return" wait, so every dead end behaves the same.
void waitForKey() {
    for (;;) {
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed())
            return;
        delay(10);
    }
}

void notReady(const Surface& s) {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);
    orthrus::ui::chrome(s.name);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Not built yet.", 8, kHeaderH + 14);
    d.setTextColor(kText, kInk);
    d.drawString(s.blurb, 8, kHeaderH + 32);

    d.setTextColor(kFaint, kInk);
    d.drawString("Shipping it empty would be", 8, kHeaderH + 54);
    d.drawString("worse than saying so.", 8, kHeaderH + 66);

    orthrus::ui::footer("any key   back");
    waitForKey();
}

void radioFailed() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);
    orthrus::ui::chrome("Airspace");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    d.drawString("Radio did not start.", 8, kHeaderH + 16);
    d.setTextColor(kMuted, kInk);
    d.drawString("Check the LoRa cap is seated", 8, kHeaderH + 34);
    d.drawString("and the antenna is fitted.", 8, kHeaderH + 46);

    orthrus::ui::footer("any key   back");
    waitForKey();
}

void openSurface(int index) {
    if (!kSurfaces[index].ready) {
        notReady(kSurfaces[index]);
        return;
    }

    if (index == 0) {
        // Static: the census table is ~13 KB and has no business on the stack.
        static orthrus::modules::Airspace airspace;
        if (!airspace.begin()) {
            radioFailed();
            return;
        }
        airspace.run();
    }
}

}  // namespace

void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    M5Cardputer.Display.setRotation(1);
    Serial.begin(115200);

    drawSplash();
    const uint32_t deadline = millis() + 6000;
    for (;;) {
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) break;
        if (millis() > deadline) break;
        delay(10);
    }
    drawMenu();
}

void loop() {
    M5Cardputer.update();

    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
        const auto ks = M5Cardputer.Keyboard.keysState();

        if (ks.enter) {
            openSurface(g_selected);
            drawMenu();
        } else {
            for (char c : ks.word) {
                if (c == kKeyUp && g_selected > 0) {
                    g_selected--;
                    drawMenu();
                } else if (c == kKeyDown && g_selected + 1 < kSurfaceCount) {
                    g_selected++;
                    drawMenu();
                }
            }
        }
    }
    delay(10);
}
