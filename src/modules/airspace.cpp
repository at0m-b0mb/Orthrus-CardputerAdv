#include "airspace.h"

#include <M5Cardputer.h>

#include <cstdio>
#include <cstring>

#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"
#include "lorawan/phy.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace lw = orthrus::lorawan;

namespace {

constexpr size_t   kMaxPhyLen   = 256;
constexpr uint32_t kRedrawMs    = 150;

// Cardputer has no arrow cluster; these are the keys everything on this board
// uses for navigation.
constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';

uint8_t popcount64(uint64_t v) {
    uint8_t n = 0;
    while (v) {
        v &= (v - 1);
        n++;
    }
    return n;
}

}  // namespace

bool Airspace::begin() {
    if (!radio_.begin()) return false;
    startedMs_ = millis();
    lastHopMs_ = startedMs_;
    retune();
    return radio_.listen();
}

void Airspace::retune() {
    const lw::ChannelPlan& p = lw::plan(region_);
    const uint8_t sweep = lw::sweepableChannels(region_);
    if (chIndex_ >= sweep) chIndex_ = 0;
    if (sfIndex_ >= p.sfCount()) sfIndex_ = 0;

    hal::RadioConfig cfg;
    cfg.freqHz = p.uplinkHz[chIndex_];
    cfg.sf     = static_cast<uint8_t>(p.sfMin + sfIndex_);
    cfg.bwKhz  = p.defaultBwKhz;
    cfg.cr     = 5;

    radio_.configure(cfg);
    radio_.listen();

    if (chIndex_ < 64) visitedChannels_ |= (1ULL << chIndex_);
    if (sfIndex_ < 64) visitedSfs_ |= (1ULL << sfIndex_);
}

void Airspace::advanceHop() {
    const uint8_t sweep = lw::sweepableChannels(region_);
    chIndex_ = static_cast<uint8_t>((chIndex_ + 1) % (sweep ? sweep : 1));
    retune();
}

uint8_t Airspace::coveredChannels() const {
    const uint8_t n = popcount64(visitedChannels_);
    return n ? n : 1;
}

uint8_t Airspace::coveredSpreadingFactors() const {
    const uint8_t n = popcount64(visitedSfs_);
    return n ? n : 1;
}

lw::CaptureContext Airspace::context() const {
    const lw::ChannelPlan& p = lw::plan(region_);
    lw::CaptureContext c;
    c.listenedMs       = millis() - startedMs_;
    c.channelsCovered  = coveredChannels();
    // Coverage is measured against the real band, not the window we sweep, so
    // US915 is honestly reported as the much worse case it is.
    c.channelsInRegion = p.uplinkCount;
    c.sfCovered        = coveredSpreadingFactors();
    c.sfInRegion       = p.sfCount();
    return c;
}

void Airspace::pump() {
    static uint8_t phy[kMaxPhyLen];
    lw::RxMeta meta;

    const int len = radio_.poll(phy, sizeof(phy), meta);
    if (len > 0) {
        lw::Frame f;
        if (lw::parse(phy, static_cast<size_t>(len), f)) {
            census_.observe(f, meta);
            lastFrameMs_ = millis();

            if (f.mtype == lw::MType::JoinRequest) {
                std::snprintf(lastLine_, sizeof(lastLine_), "JOIN %02X%02X%02X%02X %d",
                              f.join.devEui[4], f.join.devEui[5], f.join.devEui[6],
                              f.join.devEui[7], meta.rssiDbm);
            } else if (f.isData()) {
                std::snprintf(lastLine_, sizeof(lastLine_), "%08lX c%u %ddBm",
                              static_cast<unsigned long>(f.data.devAddr),
                              static_cast<unsigned>(f.data.fCnt), meta.rssiDbm);
            } else {
                std::snprintf(lastLine_, sizeof(lastLine_), "%s %ddBm",
                              lw::mtypeName(f.mtype), meta.rssiDbm);
            }
        } else {
            // A LoRa frame with a valid CRC that is not LoRaWAN. Counted, not
            // hidden: on a busy site this is how you notice a proprietary
            // network sharing the band.
            parseFailures_++;
            std::snprintf(lastLine_, sizeof(lastLine_), "non-LoRaWAN (%s)",
                          lw::errorName(f.error));
        }
    }

    if (hopping_ && (millis() - lastHopMs_) >= hopDwellMs_) {
        lastHopMs_ = millis();
        advanceHop();
    }
}

void Airspace::drawLive() {
    auto& d = M5Cardputer.Display;
    const lw::ChannelPlan& p = lw::plan(region_);
    const lw::CaptureContext ctx = context();

    d.fillScreen(kInk);

    char right[24];
    std::snprintf(right, sizeof(right), "%s %s", p.name, hopping_ ? "HOP" : "PARK");
    ui::chrome("Airspace", right);

    // Left column: what we are tuned to and what has arrived.
    d.setFont(kFaceData);
    int y = kHeaderH + 3;

    d.setTextColor(kBrass, kInk);
    d.setCursor(kPad, y);
    d.printf("%.3f MHz  SF%u", p.uplinkHz[chIndex_] / 1e6,
             static_cast<unsigned>(p.sfMin + sfIndex_));
    y += 11;

    d.setTextColor(kText, kInk);
    d.setCursor(kPad, y);
    d.printf("devices  %u", static_cast<unsigned>(census_.size()));
    y += 9;
    d.setCursor(kPad, y);
    d.printf("frames   %u", static_cast<unsigned>(census_.framesObserved()));
    y += 9;

    d.setTextColor(kMuted, kInk);
    d.setCursor(kPad, y);
    d.printf("crc err  %u", static_cast<unsigned>(radio_.stats().crcErrors));
    y += 9;
    d.setCursor(kPad, y);
    d.printf("other rf %u", static_cast<unsigned>(parseFailures_));
    y += 11;

    // Most recent decode, in the accent so the eye finds it.
    if (lastLine_[0] != '\0') {
        d.setTextColor(kShine, kInk);
        d.setCursor(kPad, y);
        d.print(lastLine_);
    }

    // Right column: the coverage grid. This is the honest bit.
    const int gridX = 168;
    const int gridY = kHeaderH + 6;
    ui::coverageGrid(gridX, gridY, static_cast<uint8_t>(p.uplinkCount > 8 ? 8 : p.uplinkCount),
                     p.sfCount(), chIndex_ < 8 ? chIndex_ : 0, sfIndex_);

    d.setFont(kFaceData);
    d.setTextColor(kMuted, kInk);
    d.setCursor(gridX, gridY + p.sfCount() * 5 + 12);
    d.printf("heard %u%%", static_cast<unsigned>(ctx.coveragePercent()));

    ui::footer("enter census   h hop   s sf   ` back");
}

void Airspace::drawCensus() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    char right[24];
    std::snprintf(right, sizeof(right), "%u seen",
                  static_cast<unsigned>(census_.size()));
    ui::chrome("Census", right);

    const lw::CaptureContext ctx = context();
    const int rows = 7;
    const int top  = kHeaderH + 2;

    if (census_.size() == 0) {
        d.setFont(kFaceData);
        d.setTextColor(kMuted, kInk);
        d.setCursor(kPad, top + 8);
        d.print("nothing heard yet.");
        d.setCursor(kPad, top + 20);
        d.print("hopping widens coverage;");
        d.setCursor(kPad, top + 29);
        d.print("uplinks can be minutes apart.");
        ui::footer("` back");
        return;
    }

    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + rows) scroll_ = selected_ - rows + 1;

    d.setFont(kFaceData);
    for (int i = 0; i < rows; i++) {
        const int idx = scroll_ + i;
        if (idx >= static_cast<int>(census_.size())) break;

        const lw::DeviceRecord& rec = census_.at(static_cast<size_t>(idx));
        const auto a = lw::assess(rec, ctx);
        const int y = top + i * 13;

        if (idx == selected_) {
            d.fillRect(0, y - 1, bd::kScreenW, 12, kSurface);
            d.drawFastVLine(0, y - 1, 12, kShine);
        }

        d.setTextColor(kText, idx == selected_ ? kSurface : kInk);
        d.setCursor(kPad + 2, y + 1);
        if (rec.kind == lw::DeviceKind::Session) {
            d.printf("%08lX", static_cast<unsigned long>(rec.devAddr));
        } else {
            d.printf("%02X%02X%02X%02X*", rec.devEui[4], rec.devEui[5],
                     rec.devEui[6], rec.devEui[7]);
        }

        d.setTextColor(kMuted, idx == selected_ ? kSurface : kInk);
        d.setCursor(kPad + 60, y + 1);
        d.printf("%3ddBm %2u", rec.bestRssiDbm, static_cast<unsigned>(rec.framesSeen));

        d.setTextColor(ui::gradeColour(a.grade), idx == selected_ ? kSurface : kInk);
        d.setCursor(bd::kScreenW - 22, y + 1);
        d.print(lw::gradeName(a.grade));
    }

    ui::footer("enter dossier   ; . move   ` back");
}

void Airspace::drawDossier() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    if (census_.size() == 0) {
        view_ = View::Census;
        return;
    }
    if (selected_ >= static_cast<int>(census_.size())) selected_ = 0;

    const lw::DeviceRecord& rec = census_.at(static_cast<size_t>(selected_));
    const lw::CaptureContext ctx = context();
    const auto a = lw::assess(rec, ctx);

    char title[24];
    if (rec.kind == lw::DeviceKind::Session) {
        std::snprintf(title, sizeof(title), "%08lX",
                      static_cast<unsigned long>(rec.devAddr));
    } else {
        std::snprintf(title, sizeof(title), "%02X%02X%02X%02X", rec.devEui[4],
                      rec.devEui[5], rec.devEui[6], rec.devEui[7]);
    }
    ui::chrome("Dossier", title);

    // Grade, set large in the serif face -- the one moment of identity type.
    d.setFont(kFaceIdentity);
    d.setTextColor(ui::gradeColour(a.grade), kInk);
    d.setCursor(kPad, kHeaderH + 4);
    d.print(lw::gradeName(a.grade));

    d.setFont(kFaceData);
    d.setTextColor(kMuted, kInk);
    d.setCursor(kPad + 34, kHeaderH + 10);
    d.printf("%u/100  %u frames", static_cast<unsigned>(a.score),
             static_cast<unsigned>(rec.framesSeen));

    int y = kHeaderH + 26;
    if (a.findings.count == 0) {
        d.setTextColor(kGood, kInk);
        d.setCursor(kPad, y);
        d.print("nothing adverse observed.");
        y += 11;
        d.setTextColor(kFaint, kInk);
        d.setCursor(kPad, y);
        d.print("absence of evidence only.");
    }

    for (uint8_t i = 0; i < a.findings.count && y < bd::kScreenH - kFooterH - 8; i++) {
        const lw::Finding& f = a.findings.items[i];
        d.setTextColor(ui::severityColour(f.sev), kInk);
        d.setCursor(kPad, y);
        d.print(lw::findingTitle(f.id));

        // Confidence sits right-flush: it is the number that stops this being
        // an accusation.
        ui::textRight(bd::kScreenW - kPad, y, kFaint, "%u%%",
                      static_cast<unsigned>(f.confidence));
        y += 11;
    }

    ui::footer("; . device   ` back");
}

bool Airspace::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (ks.enter) {
        if (view_ == View::Live) view_ = View::Census;
        else if (view_ == View::Census) view_ = View::Dossier;
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Dossier) view_ = View::Census;
                else if (view_ == View::Census) view_ = View::Live;
                else return false;  // leave the module
                return true;

            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (selected_ + 1 < static_cast<int>(census_.size())) selected_++;
                return true;

            case 'h':
                hopping_ = !hopping_;
                lastHopMs_ = millis();
                return true;

            case 's': {
                // Step the spreading factor. Widening SF coverage costs dwell
                // time on each, which is the real trade the operator is making.
                const lw::ChannelPlan& p = lw::plan(region_);
                sfIndex_ = static_cast<uint8_t>((sfIndex_ + 1) % p.sfCount());
                retune();
                return true;
            }

            case 'r': {
                region_ = lw::regionAt(
                    (static_cast<size_t>(region_) + 1) % lw::regionCount());
                chIndex_ = 0;
                sfIndex_ = 0;
                visitedChannels_ = 0;
                visitedSfs_      = 0;
                retune();
                return true;
            }

            default:
                break;
        }
    }
    return true;
}

void Airspace::run() {
    for (;;) {
        M5Cardputer.update();
        pump();

        if (!handleKeys()) return;

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Live:    drawLive();    break;
                case View::Census:  drawCensus();  break;
                case View::Dossier: drawDossier(); break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
