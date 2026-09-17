#include "sys_evidence.h"

#include <M5Cardputer.h>
#include <SD.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "evidence/export.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace ev = orthrus::evidence;

namespace {
constexpr int  kBodyTop = 21;
constexpr int  kRowH    = 13;
constexpr int  kLabelX  = 6;
constexpr int  kValueX  = 234;
constexpr char kKeyBack = '`';
}  // namespace

bool SysEvidence::begin() {
    gnss_.begin();
    app::recorder().begin();  // a missing card is a state, not a failure
    return true;
}

void SysEvidence::exportKml() {
    const auto& rec = app::recorder();
    if (!rec.active()) {
        resultOk_ = false;
        std::snprintf(resultTitle_, sizeof(resultTitle_), "No session");
        std::snprintf(resultBody_, sizeof(resultBody_),
                      "Insert a microSD card and reopen this screen.");
        view_ = View::Result;
        return;
    }

    char kmlPath[48];
    std::snprintf(kmlPath, sizeof(kmlPath), "%s", rec.path());
    char* dot = std::strrchr(kmlPath, '.');

    // Refuse rather than risk it. With no extension the derived path would
    // equal the log path, and opening that for writing TRUNCATES the evidence
    // file -- destroying the very thing we are exporting.
    if (dot == nullptr || dot == kmlPath) {
        resultOk_ = false;
        std::snprintf(resultTitle_, sizeof(resultTitle_), "Refused");
        std::snprintf(resultBody_, sizeof(resultBody_),
                      "Log path has no extension, so the export would overwrite "
                      "it. Nothing was written.");
        view_ = View::Result;
        return;
    }
    std::snprintf(dot, sizeof(kmlPath) - (dot - kmlPath), ".kml");

    // Belt and braces: if the two paths still match, stop.
    if (std::strcmp(kmlPath, rec.path()) == 0) {
        resultOk_ = false;
        std::snprintf(resultTitle_, sizeof(resultTitle_), "Refused");
        std::snprintf(resultBody_, sizeof(resultBody_),
                      "Export path matches the log path. Nothing was written.");
        view_ = View::Result;
        return;
    }

    File in = SD.open(rec.path(), FILE_READ);
    if (!in) {
        resultOk_ = false;
        std::snprintf(resultTitle_, sizeof(resultTitle_), "Cannot read log");
        std::snprintf(resultBody_, sizeof(resultBody_), "%s", rec.path());
        view_ = View::Result;
        return;
    }

    File out = SD.open(kmlPath, FILE_WRITE);
    if (!out) {
        in.close();
        resultOk_ = false;
        std::snprintf(resultTitle_, sizeof(resultTitle_), "Cannot write KML");
        std::snprintf(resultBody_, sizeof(resultBody_), "%s", kmlPath);
        view_ = View::Result;
        return;
    }

    char buf[1536];  // a full-length escaped detail needs ~900
    ev::kmlHeader(buf, sizeof(buf), rec.path());
    out.print(buf);

    uint32_t placed = 0, lines = 0;
    char line[320];

    // Skip the CSV header row.
    in.readBytesUntil('\n', line, sizeof(line) - 1);

    while (in.available()) {
        const size_t n = in.readBytesUntil('\n', line, sizeof(line) - 1);
        if (n == 0) continue;
        line[n] = '\0';
        lines++;

        ev::Record r;
        char field[32];
        if (ev::csvField(line, 0, field, sizeof(field))) r.seq = std::strtoul(field, nullptr, 10);
        if (ev::csvField(line, 1, field, sizeof(field))) r.timeMs = std::strtoul(field, nullptr, 10);
        if (!ev::csvField(line, 3, r.detail, ev::kDetailLen)) continue;

        const ev::Position p = ev::positionOf(r);
        if (!p.valid) continue;  // no fix when it was recorded; not a failure

        if (ev::kmlPlacemark(buf, sizeof(buf), r, p) > 0) {
            out.print(buf);
            placed++;
        }
    }

    ev::kmlFooter(buf, sizeof(buf));
    out.print(buf);
    out.close();
    in.close();

    resultOk_ = true;
    std::snprintf(resultTitle_, sizeof(resultTitle_), "Exported");
    if (placed == 0) {
        // Honest about the usual reason: indoors there is no fix, so there is
        // nothing to place, and a silently empty map is worse than a sentence.
        std::snprintf(resultBody_, sizeof(resultBody_),
                      "%lu records, 0 had a GPS fix. Nothing to map yet.",
                      static_cast<unsigned long>(lines));
    } else {
        std::snprintf(resultBody_, sizeof(resultBody_),
                      "%lu placemarks from %lu records.",
                      static_cast<unsigned long>(placed),
                      static_cast<unsigned long>(lines));
    }
    view_ = View::Result;
}

void SysEvidence::draw() {
    ui::beginFrame();
    auto& d = ui::gfx();
    auto& rec = app::recorder();

    ui::chrome("Evidence", rec.active() ? "logging" : "no card");

    d.setFont(kFaceData);
    int y = kBodyTop + 6;

    ui::textAt(kLabelX, y, kMuted, "log");
    if (rec.active()) ui::textRight(kValueX, y, kText, "%s", rec.path());
    else              ui::textRight(kValueX, y, kCritical, "%s", rec.lastError());
    y += kRowH;

    // The card itself, separately from the session. "No card" and "a card that
    // mounted but the session file would not open" need different responses
    // from the operator, and one line reading "no card" for both is what makes
    // a working card look broken.
    ui::textAt(kLabelX, y, kMuted, "card");
    if (rec.cardMiB()) {
        ui::textRight(kValueX, y, kText, "%lu MB at %lu MHz",
                      static_cast<unsigned long>(rec.cardMiB()),
                      static_cast<unsigned long>(rec.mountHz() / 1000000));
    } else if (!rec.attempted()) {
        ui::textRight(kValueX, y, kFaint, "not looked yet");
    } else {
        ui::textRight(kValueX, y, kCritical, "not mounted -- r to retry");
    }
    y += kRowH;

    ui::textAt(kLabelX, y, kMuted, "records");
    ui::textRight(kValueX, y, kText, "%lu",
                  static_cast<unsigned long>(rec.count()));
    y += kRowH;

    ui::textAt(kLabelX, y, kMuted, "gnss");
    if (gnss_.hasFix()) {
        ui::textRight(kValueX, y, kGood, "fix, findings geotagged");
    } else if (gnss_.alive()) {
        ui::textRight(kValueX, y, kBrass, "searching, %lu sats",
                      static_cast<unsigned long>(gnss_.satellites()));
    } else {
        ui::textRight(kValueX, y, kFaint, "no data");
    }
    y += kRowH + 4;

    // The head digest, which is the whole point of the screen.
    d.drawFastHLine(6, y - 4, bd::kScreenW - 12, kRule);
    ui::textAt(kLabelX, y + 6, kBrass, "chain head");
    if (rec.active()) {
        char shortHex[24];
        rec.headShort(shortHex);
        d.setFont(kFaceData);
        d.setTextDatum(middle_right);
        d.setTextColor(kShine, kInk);
        d.drawString(shortHex, kValueX, y + 6);
        d.setTextDatum(top_left);

        ui::wrapText(kLabelX, y + 16, bd::kScreenW - 12, 10, 2, kFaint,
                     "Photograph this. A log verified against a head recorded "
                     "away from the card is tamper-evident.");
    } else {
        ui::textRight(kValueX, y + 6, kFaint, "no session");
    }

    ui::footer(rec.active() ? "e export KML   ` back"
                            : "r retry card   ` back");
    ui::endFrame();
}

void SysEvidence::drawResult() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome(resultTitle_);

    d.setFont(kFaceData);
    ui::wrapText(8, kBodyTop + 10, bd::kScreenW - 16, 12, 4,
                 resultOk_ ? kText : kCritical, resultBody_);

    ui::footer("any key   back");
    ui::endFrame();
}

bool SysEvidence::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    if (view_ == View::Result) {
        view_ = View::Status;
        return true;
    }

    const auto ks = M5Cardputer.Keyboard.keysState();
    for (char c : ks.word) {
        if (c == kKeyBack) return false;
        if (c == 'e') { exportKml(); return true; }
        if (c == 'r') {
            // The mount is deliberately attempted once per boot so a missing
            // card cannot stall every capture loop. This is the operator
            // saying they have just seated it properly.
            app::recorder().retry();
            return true;
        }
    }
    return true;
}

void SysEvidence::run() {
    for (;;) {
        M5Cardputer.update();
        gnss_.pump();

        if (!handleKeys()) return;

        if (millis() - lastDrawMs_ >= 200) {
            lastDrawMs_ = millis();
            if (view_ == View::Status) draw();
            else                       drawResult();
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
