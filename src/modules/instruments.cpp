#include "instruments.h"

#include <M5Cardputer.h>

#include <cstdio>

#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;

namespace {

constexpr uint32_t kSampleMs = 80;
constexpr uint32_t kDrawMs   = 120;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 13;
constexpr int kLabelX  = 6;
constexpr int kValueX  = 150;   // values flush right to here, clear of the dial

constexpr char kKeyBack = '`';

}  // namespace

bool Instruments::begin() {
    gnss_.begin();
    // The radio is optional here. If the cap is missing, every other reading
    // still works and the radio line says so rather than the screen refusing.
    radioUp_   = radio_.begin();
    if (radioUp_) radio_.listen();
    startedMs_ = millis();
    minHeap_   = ESP.getFreeHeap();
    return true;
}

void Instruments::sample() {
    if (millis() - lastSampleMs_ < kSampleMs) return;
    lastSampleMs_ = millis();

    gnss_.pump();

    if (radioUp_) {
        const float v = radio_.instantRssi();
        if (v != 0.0f) rssi_ = v;
    }

    if (M5.Imu.isEnabled()) {
        M5.Imu.update();
        M5.Imu.getAccel(&ax_, &ay_, &az_);
    }

    const uint32_t heap = ESP.getFreeHeap();
    if (heap < minHeap_) minHeap_ = heap;
}

// A bubble level driven by the accelerometer. The signature element here for
// the same reason the coverage grid is Airspace's: it is made of real sensor
// data, it moves the instant you tilt the device, and nothing else on the
// screen proves quite so immediately that the hardware is alive.
void Instruments::drawBubble(int cx, int cy, int r) {
    auto& d = ui::gfx();

    d.drawCircle(cx, cy, r, kRule);
    d.drawCircle(cx, cy, r / 2, kRule);
    d.drawFastHLine(cx - r, cy, r * 2, kRule);
    d.drawFastVLine(cx, cy - r, r * 2, kRule);

    // 1 g of tilt maps to the rim. Clamped so a sharp knock parks the bubble at
    // the edge rather than drawing it off the dial.
    int bx = static_cast<int>(ax_ * r);
    int by = static_cast<int>(ay_ * r);
    const int lim = r - 3;
    if (bx > lim) bx = lim;
    if (bx < -lim) bx = -lim;
    if (by > lim) by = lim;
    if (by < -lim) by = -lim;

    // Level within a few degrees reads green; otherwise the accent.
    const bool level = (bx * bx + by * by) < (r / 4) * (r / 4);
    d.fillCircle(cx + bx, cy - by, 3, level ? kGood : kShine);
}

void Instruments::draw() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%d%%", M5.Power.getBatteryLevel());
    ui::chrome("Instruments", right);

    d.setFont(kFaceData);
    int y = kBodyTop + 6;

    // ---- power -------------------------------------------------------------
    const int32_t batt = M5.Power.getBatteryLevel();
    const int32_t mv   = M5.Power.getBatteryVoltage();
    ui::textAt(kLabelX, y, kMuted, "battery");
    ui::textRight(kValueX, y, batt > 20 ? kText : kCritical, "%ld%%  %ld.%02ld V",
                  static_cast<long>(batt), static_cast<long>(mv / 1000),
                  static_cast<long>((mv % 1000) / 10));
    y += kRowH;

    // ---- memory ------------------------------------------------------------
    ui::textAt(kLabelX, y, kMuted, "heap");
    ui::textRight(kValueX, y, kText, "%lu K  low %lu K",
                  static_cast<unsigned long>(ESP.getFreeHeap() / 1024),
                  static_cast<unsigned long>(minHeap_ / 1024));
    y += kRowH;

    // ---- uptime ------------------------------------------------------------
    const uint32_t up = (millis() - startedMs_) / 1000;
    ui::textAt(kLabelX, y, kMuted, "uptime");
    ui::textRight(kValueX, y, kText, "%02lu:%02lu:%02lu",
                  static_cast<unsigned long>(up / 3600),
                  static_cast<unsigned long>((up / 60) % 60),
                  static_cast<unsigned long>(up % 60));
    y += kRowH;

    // ---- radio -------------------------------------------------------------
    ui::textAt(kLabelX, y, kMuted, "radio");
    if (radioUp_) ui::textRight(kValueX, y, kText, "%d dBm floor",
                                static_cast<int>(rssi_));
    else          ui::textRight(kValueX, y, kFaint, "no cap");
    y += kRowH;

    // ---- gnss --------------------------------------------------------------
    // Three distinct states, shown three distinct ways. Collapsing "searching"
    // into "no data" is exactly what makes a working GPS look broken.
    ui::textAt(kLabelX, y, kMuted, "gnss");
    if (!gnss_.alive()) {
        ui::textRight(kValueX, y, kFaint, "no data");
    } else if (gnss_.hasFix()) {
        ui::textRight(kValueX, y, kGood, "fix  %lu sats",
                      static_cast<unsigned long>(gnss_.satellites()));
    } else {
        ui::textRight(kValueX, y, kBrass, "search %lu sats",
                      static_cast<unsigned long>(gnss_.satellites()));
    }
    y += kRowH;

    // Position or sentence count, whichever we actually have.
    ui::textAt(kLabelX, y, kMuted, "position");
    if (gnss_.hasFix()) {
        ui::textRight(kValueX, y, kText, "%.4f %.4f", gnss_.latitude(),
                      gnss_.longitude());
    } else {
        ui::textRight(kValueX, y, kFaint, "%lu NMEA msg",
                      static_cast<unsigned long>(gnss_.sentences()));
    }
    y += kRowH;

    // ---- attitude ----------------------------------------------------------
    ui::textAt(kLabelX, y, kMuted, "tilt");
    ui::textRight(kValueX, y, kText, "%+.2f %+.2f g", ax_, ay_);

    drawBubble(196, kBodyTop + 34, 26);

    ui::footer("live  -  ` back");
    ui::endFrame();
}

void Instruments::run() {
    for (;;) {
        M5Cardputer.update();
        sample();

        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            const auto ks = M5Cardputer.Keyboard.keysState();
            for (char c : ks.word) {
                if (c == kKeyBack) {
                    if (radioUp_) radio_.idle();
                    return;
                }
            }
        }

        if (millis() - lastDrawMs_ >= kDrawMs) {
            lastDrawMs_ = millis();
            draw();
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
