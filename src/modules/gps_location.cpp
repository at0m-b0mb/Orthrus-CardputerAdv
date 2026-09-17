#include "gps_location.h"

#include <M5Cardputer.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "geo/position.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;

namespace {

constexpr uint32_t kRedrawMs = 250;
constexpr uint32_t kTrackMs  = 10000;   // one track point every ten seconds

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyBack  = '`';
constexpr char kKeyMark  = 'm';
constexpr char kKeyTrack = 't';
constexpr char kKeyList  = 'w';

// The device face draws its degree glyph at 0xF8 rather than at the Latin-1
// codepoint, which is why formatDms takes the mark as a parameter at all.
constexpr const char* kDegree = "\xF8";

uint16_t geometryColour(geo::Geometry g) {
    switch (g) {
        case geo::Geometry::Ideal:
        case geo::Geometry::Excellent: return kGood;
        case geo::Geometry::Good:      return kLow;
        case geo::Geometry::Moderate:  return kMedium;
        case geo::Geometry::Poor:      return kHigh;
        case geo::Geometry::Unusable:  return kCritical;
        case geo::Geometry::Unknown:   return kFaint;
    }
    return kFaint;
}

}  // namespace

bool GpsLocation::begin() {
    gnss_.begin();
    enteredMs_ = millis();
    return true;
}

void GpsLocation::pump() {
    gnss_.pump();

    if (!tracking_) return;
    if (millis() - lastTrackMs_ < kTrackMs) return;
    lastTrackMs_ = millis();

    if (!gnss_.hasFix()) return;
    const double lat = gnss_.latitude();
    const double lon = gnss_.longitude();
    if (!geo::plausible(lat, lon)) return;

    char detail[96];
    std::snprintf(detail, sizeof(detail), "track lat=%.6f lon=%.6f sat=%u err=%um",
                  lat, lon, static_cast<unsigned>(gnss_.satellites()),
                  static_cast<unsigned>(geo::estimatedErrorMeters(gnss_.hdop())));
    if (app::recorder().note(evidence::RecordKind::Note, detail)) trackPoints_++;
}

bool GpsLocation::mark() {
    markError_ = nullptr;

    if (!gnss_.alive()) {
        markError_ = "No NMEA. Check the cap is seated.";
        return false;
    }
    if (!gnss_.hasFix()) {
        markError_ = "No fix yet. Nothing to mark.";
        return false;
    }

    const double lat = gnss_.latitude();
    const double lon = gnss_.longitude();
    if (!geo::plausible(lat, lon)) {
        markError_ = "Receiver reported an impossible fix.";
        return false;
    }
    if (waypointCount_ >= kMaxWaypoints) {
        markError_ = "Waypoint list is full.";
        return false;
    }

    Waypoint& w = waypoints_[waypointCount_++];
    w.lat        = lat;
    w.lon        = lon;
    w.errorM     = geo::estimatedErrorMeters(gnss_.hdop());
    w.atMs       = millis();
    w.satellites = static_cast<uint8_t>(gnss_.satellites());

    // Into the evidence chain, not just into RAM. A waypoint that only exists
    // on the screen is a waypoint that dies with the battery, and the whole
    // point of marking one is that it reaches the report.
    char detail[96];
    std::snprintf(detail, sizeof(detail),
                  "waypoint %u lat=%.6f lon=%.6f sat=%u err=%um",
                  static_cast<unsigned>(waypointCount_), lat, lon,
                  static_cast<unsigned>(w.satellites),
                  static_cast<unsigned>(w.errorM));
    if (!app::recorder().noteDevice(detail)) {
        markError_ = "Marked on screen, but the card refused it.";
        return false;
    }
    return true;
}

// ---- screens ----------------------------------------------------------------

void GpsLocation::skyMeter(int x, int y, int w, uint32_t satellites) {
    auto& d = ui::gfx();
    // Twelve cells. A consumer receiver tracking twelve satellites is doing as
    // well as it is going to, so twelve is full scale rather than an arbitrary
    // maximum nobody reaches.
    constexpr int kCells = 12;
    const int cell = (w - (kCells - 1) * 2) / kCells;

    for (int i = 0; i < kCells; i++) {
        const int cx = x + i * (cell + 2);
        if (static_cast<uint32_t>(i) < satellites)
            d.fillRect(cx, y, cell, 6, kShine);
        else
            d.drawRect(cx, y, cell, 6, kRule);
    }
}

void GpsLocation::drawLive() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[20];
    if (tracking_) {
        std::snprintf(right, sizeof(right), "track %u",
                      static_cast<unsigned>(trackPoints_));
    } else {
        std::snprintf(right, sizeof(right), "%u sat",
                      static_cast<unsigned>(gnss_.satellites()));
    }
    ui::chrome("Location", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (!gnss_.alive()) {
        d.setTextColor(kCritical, kInk);
        d.drawString("No NMEA from the receiver.", 8, kBodyTop + 6);
        ui::wrapText(8, kBodyTop + 22, bd::kScreenW - 16, 11, 4, kMuted,
                     "Nothing is arriving at all. That is a seating or wiring "
                     "problem, not a sky problem: check the LoRa cap is pushed "
                     "fully home.");
        ui::textAt(8, bd::kScreenH - kFooterH - 10, kFaint, "%u bytes seen",
                   static_cast<unsigned>(gnss_.bytes()));
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    if (!gnss_.hasFix()) {
        d.setTextColor(kMedium, kInk);
        d.drawString("Receiving. No fix yet.", 8, kBodyTop + 6);

        skyMeter(8, kBodyTop + 22, bd::kScreenW - 16, gnss_.satellites());

        ui::textAt(8, kBodyTop + 40, kMuted, "%u satellites   %us searching",
                   static_cast<unsigned>(gnss_.satellites()),
                   static_cast<unsigned>((millis() - enteredMs_) / 1000));

        // The distinction that saves an hour: a receiver failing its own
        // checksums is a wiring fault that looks exactly like a bad sky.
        const uint32_t bad = gnss_.checksumFailures();
        if (bad > 4) {
            ui::textAt(8, kBodyTop + 54, kHigh, "%u bad checksums",
                       static_cast<unsigned>(bad));
            ui::wrapText(8, kBodyTop + 66, bd::kScreenW - 16, 10, 2, kFaint,
                         "Sentences are arriving corrupted. That is the cable, not "
                         "the sky.");
        } else {
            ui::wrapText(8, kBodyTop + 54, bd::kScreenW - 16, 10, 3, kFaint,
                         "A cold start under open sky takes about a minute. Indoors "
                         "it may never come, and that is the receiver being honest.");
        }

        ui::footer("t track   ` back");
        ui::endFrame();
        return;
    }

    // ---- we have a fix ----
    const double lat = gnss_.latitude();
    const double lon = gnss_.longitude();
    const double hdop = gnss_.hdop();
    const geo::Geometry geom = geo::geometryFor(hdop);
    const uint16_t err = geo::estimatedErrorMeters(hdop);

    char latDms[24], lonDms[24];
    if (geo::formatDms(lat, true, latDms, sizeof(latDms), kDegree) == 0)
        std::snprintf(latDms, sizeof(latDms), "%.5f", lat);
    if (geo::formatDms(lon, false, lonDms, sizeof(lonDms), kDegree) == 0)
        std::snprintf(lonDms, sizeof(lonDms), "%.5f", lon);

    ui::textAt(8, kBodyTop + 5, kText, "%s", latDms);
    ui::textAt(8, kBodyTop + 17, kText, "%s", lonDms);
    ui::textAt(8, kBodyTop + 29, kFaint, "%.5f %.5f", lat, lon);

    // The radius, not just the coordinates. Six decimal places is a centimetre,
    // and this receiver does not have one.
    d.setTextDatum(middle_right);
    d.setTextColor(geometryColour(geom), kInk);
    d.setFont(kFaceUi);
    char radius[16];
    if (err) std::snprintf(radius, sizeof(radius), "+/-%um", static_cast<unsigned>(err));
    else     std::snprintf(radius, sizeof(radius), "+/-?");
    d.drawString(radius, bd::kScreenW - 6, kBodyTop + 12);
    d.setFont(kFaceData);
    ui::textRight(bd::kScreenW - 6, kBodyTop + 28, kFaint, "%s",
                  geo::geometryName(geom));

    d.drawFastHLine(6, kBodyTop + 38, bd::kScreenW - 12, kRule);

    skyMeter(8, kBodyTop + 44, 104, gnss_.satellites());
    ui::textAt(118, kBodyTop + 47, kMuted, "%u sat",
               static_cast<unsigned>(gnss_.satellites()));

    if (gnss_.hasAltitude())
        ui::textRight(bd::kScreenW - 6, kBodyTop + 47, kMuted, "%.0f m",
                      gnss_.altitudeMeters());

    int y = kBodyTop + 60;
    if (gnss_.hasTime()) {
        ui::textAt(8, y, kFaint, "%02u:%02u:%02u UTC",
                   static_cast<unsigned>(gnss_.hour()),
                   static_cast<unsigned>(gnss_.minute()),
                   static_cast<unsigned>(gnss_.second()));
    }
    if (gnss_.hasSpeed() && gnss_.speedKmph() > 1.0)
        ui::textRight(bd::kScreenW - 6, y, kFaint, "%.1f km/h", gnss_.speedKmph());

    if (waypointCount_)
        ui::textAt(8, y + 12, kBrass, "%u waypoint%s",
                   static_cast<unsigned>(waypointCount_),
                   waypointCount_ == 1 ? "" : "s");
    if (markError_)
        ui::textAt(8, y + 12, kHigh, "%.34s", markError_);

    d.setTextDatum(top_left);
    ui::footer("m mark  t track  w list  ` back");
    ui::endFrame();
}

void GpsLocation::drawWaypoints() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u", static_cast<unsigned>(waypointCount_));
    ui::chrome("Waypoints", right);

    if (waypointCount_ == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString("Nothing marked yet.", 8, kBodyTop + 8);
        ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 3, kFaint,
                     "Press m on the live screen to mark where you are standing. "
                     "Every mark goes into the evidence log.");
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    if (selected_ >= waypointCount_) selected_ = waypointCount_ - 1;
    if (selected_ < 0) selected_ = 0;

    const int rows = bd::kScreenH - kFooterH - kBodyTop;
    const int maxRows = rows / kRowH;
    int start = selected_ - maxRows + 1;
    if (start < 0) start = 0;

    for (int i = 0; i < maxRows; i++) {
        const int idx = start + i;
        if (idx >= waypointCount_) break;

        const Waypoint& w = waypoints_[idx];
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);
        d.setTextColor(kBrass, bg);
        char label[8];
        std::snprintf(label, sizeof(label), "%02d", idx + 1);
        d.drawString(label, 8, mid);

        d.setTextColor(kText, bg);
        char pos[32];
        std::snprintf(pos, sizeof(pos), "%.4f %.4f", w.lat, w.lon);
        d.drawString(pos, 28, mid);

        d.setTextDatum(middle_right);
        d.setTextColor(kFaint, bg);
        char err[10];
        std::snprintf(err, sizeof(err), "%um", static_cast<unsigned>(w.errorM));
        d.drawString(err, bd::kScreenW - 6, mid);
    }

    // How far the operator has walked from the point they are looking at. The
    // most common question in front of this list.
    if (gnss_.hasFix() && geo::plausible(gnss_.latitude(), gnss_.longitude())) {
        const double m = geo::distanceMeters(gnss_.latitude(), gnss_.longitude(),
                                             waypoints_[selected_].lat,
                                             waypoints_[selected_].lon);
        char hint[40];
        std::snprintf(hint, sizeof(hint), "%.0f m from here", m);
        ui::footer(hint);
    } else {
        ui::footer("; . move   ` back");
    }

    d.setTextDatum(top_left);
    ui::endFrame();
}

void GpsLocation::drawMarked() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Marked");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    const Waypoint& w = waypoints_[waypointCount_ - 1];
    d.setTextColor(kGood, kInk);
    ui::textAt(8, kBodyTop + 10, kGood, "Waypoint %u marked",
               static_cast<unsigned>(waypointCount_));

    d.setTextColor(kText, kInk);
    char pos[40];
    std::snprintf(pos, sizeof(pos), "%.6f, %.6f", w.lat, w.lon);
    d.drawString(pos, 8, kBodyTop + 24);

    d.setTextColor(kMuted, kInk);
    char meta[40];
    std::snprintf(meta, sizeof(meta), "+/- %u m   %u satellites",
                  static_cast<unsigned>(w.errorM),
                  static_cast<unsigned>(w.satellites));
    d.drawString(meta, 8, kBodyTop + 38);

    ui::wrapText(8, kBodyTop + 56, bd::kScreenW - 16, 10, 3, kFaint,
                 "Written to the evidence log. It comes out in the KML export "
                 "alongside every other finding from this session.");

    ui::footer("any key   back");
    ui::endFrame();
}

bool GpsLocation::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Marked) {
        view_ = View::Live;
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Waypoints) { view_ = View::Live; return true; }
                return false;

            case kKeyMark:
                if (view_ == View::Live && mark()) view_ = View::Marked;
                return true;

            case kKeyTrack:
                tracking_ = !tracking_;
                // Logging from the moment it is switched on rather than ten
                // seconds later: the operator pressed the key where they are
                // standing now.
                if (tracking_) lastTrackMs_ = millis() - kTrackMs;
                return true;

            case kKeyList:
                if (view_ == View::Live) { view_ = View::Waypoints; return true; }
                return true;

            case kKeyUp:
                if (view_ == View::Waypoints && selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (view_ == View::Waypoints && selected_ + 1 < waypointCount_)
                    selected_++;
                return true;

            default:
                break;
        }
    }
    return true;
}

void GpsLocation::run() {
    lastDrawMs_ = 0;
    enteredMs_  = millis();

    for (;;) {
        M5Cardputer.update();
        pump();

        if (!handleKeys()) return;

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Live:      drawLive();      break;
                case View::Waypoints: drawWaypoints(); break;
                case View::Marked:    drawMarked();    break;
            }
        }
        delay(5);
    }
}

}  // namespace orthrus::modules
