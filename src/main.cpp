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

struct Surface {
    const char* name;
    const char* blurb;
    bool        ready;
};

// Product vocabulary, not framework vocabulary. Each name is what the operator
// is actually pointing the device at.
const Surface kSurfaces[] = {
    {"Airspace",    "LoRa and LoRaWAN census",   true},
    {"Perimeter",   "Wi-Fi recon and portals",   false},
    {"Credentials", "NFC and 125 kHz badges",    false},
    {"Control",     "Infrared and USB payloads", false},
    {"Engagement",  "Scope, log, and export",    false},
};
constexpr int kSurfaceCount = sizeof(kSurfaces) / sizeof(kSurfaces[0]);

int g_selected = 0;

void drawSplash() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    d.setFont(kFaceIdentity);
    d.setTextColor(kText, kInk);
    d.setCursor(16, 34);
    d.print("ORTHRUS");

    d.setFont(kFaceData);
    d.setTextColor(kBrass, kInk);
    d.setCursor(18, 58);
    d.print("multi-surface red team platform");

    d.setTextColor(kFaint, kInk);
    d.setCursor(18, 72);
    d.printf("v%s   authorized testing only", kVersion);

    // A single gold rule, the only ornament in the whole product.
    d.drawFastHLine(16, 88, 120, kShine);

    d.setTextColor(kMuted, kInk);
    d.setCursor(18, 98);
    d.print("press any key");
}

void drawMenu() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    char batt[16];
    std::snprintf(batt, sizeof(batt), "%d%%", M5.Power.getBatteryLevel());
    orthrus::ui::chrome("Surfaces", batt);

    const int top = kHeaderH + 3;
    for (int i = 0; i < kSurfaceCount; i++) {
        const int y = top + i * 21;
        const bool sel = (i == g_selected);

        if (sel) {
            d.fillRect(0, y - 1, bd::kScreenW, 20, kSurface);
            d.drawFastVLine(0, y - 1, 20, kShine);
        }

        d.setFont(kFaceUi);
        d.setTextColor(kSurfaces[i].ready ? kText : kFaint, sel ? kSurface : kInk);
        d.setCursor(8, y + 1);
        d.print(kSurfaces[i].name);

        d.setFont(kFaceData);
        d.setTextColor(kMuted, sel ? kSurface : kInk);
        d.setCursor(8, y + 13);
        d.print(kSurfaces[i].blurb);

        if (!kSurfaces[i].ready) {
            d.setTextColor(kFaint, sel ? kSurface : kInk);
            orthrus::ui::textRight(bd::kScreenW - 4, y + 6, kFaint, "soon");
        }
    }

    orthrus::ui::footer("; . move    enter open");
}

void notReady(const Surface& s) {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);
    orthrus::ui::chrome(s.name);

    d.setFont(kFaceData);
    d.setTextColor(kMuted, kInk);
    d.setCursor(6, kHeaderH + 14);
    d.print("not built yet.");
    d.setCursor(6, kHeaderH + 28);
    d.print(s.blurb);
    d.setCursor(6, kHeaderH + 46);
    d.setTextColor(kFaint, kInk);
    d.print("shipping it empty would be");
    d.setCursor(6, kHeaderH + 55);
    d.print("worse than saying so.");

    orthrus::ui::footer("` back");

    for (;;) {
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed())
            return;
        delay(10);
    }
}

void openSurface(int index) {
    if (!kSurfaces[index].ready) {
        notReady(kSurfaces[index]);
        return;
    }

    if (index == 0) {
        static orthrus::modules::Airspace airspace;
        if (!airspace.begin()) {
            auto& d = M5Cardputer.Display;
            d.fillScreen(kInk);
            orthrus::ui::chrome("Airspace");
            d.setFont(kFaceData);
            d.setTextColor(kCritical, kInk);
            d.setCursor(6, kHeaderH + 16);
            d.print("radio did not start.");
            d.setTextColor(kMuted, kInk);
            d.setCursor(6, kHeaderH + 30);
            d.print("check the LoRa cap is seated.");
            orthrus::ui::footer("` back");
            for (;;) {
                M5Cardputer.update();
                if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed())
                    return;
                delay(10);
            }
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
    const uint32_t deadline = millis() + 8000;
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
