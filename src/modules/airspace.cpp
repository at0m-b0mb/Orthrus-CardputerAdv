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

constexpr size_t   kMaxPhyLen = 256;
constexpr uint32_t kRedrawMs  = 180;

// Cardputer has no arrow cluster; these are the keys every project on this
// board uses for navigation.
constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';

// Layout, written down once. See main.cpp for why.
constexpr int kBodyTop    = 21;
constexpr int kCensusRowH = 14;
constexpr int kCensusRows = 6;
constexpr int kGridX      = 180;
constexpr int kGridY      = 26;

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
    // Measured against the real band, not the window we sweep, so US915 is
    // honestly reported as the much worse case it is.
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
                std::snprintf(lastLine_, sizeof(lastLine_), "JOIN %02X%02X%02X%02X %ddBm",
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
            // hidden: on a live site this is how you notice a proprietary
            // network sharing the band.
            parseFailures_++;
            std::snprintf(lastLine_, sizeof(lastLine_), "non-LoRaWAN frame");
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

    char right[20];
    std::snprintf(right, sizeof(right), "%s %s", p.name, hopping_ ? "HOP" : "PARK");
    ui::chrome("Airspace", right);

    d.setFont(kFaceData);

    // Tuning, in the accent: it is the one thing that changes as you hop.
    char tune[32];
    std::snprintf(tune, sizeof(tune), "%.3f MHz   SF%u", p.uplinkHz[chIndex_] / 1e6,
                  static_cast<unsigned>(p.sfMin + sfIndex_));
    ui::textAt(6, kBodyTop + 5, kShine, "%s", tune);

    // Counters. Devices and frames are what you came for; the error counts are
    // what stop an empty list being mistaken for a quiet band.
    ui::textAt(6, kBodyTop + 24, kMuted, "devices");
    ui::textRight(96, kBodyTop + 24, kText, "%u", static_cast<unsigned>(census_.size()));

    ui::textAt(6, kBodyTop + 37, kMuted, "frames");
    ui::textRight(96, kBodyTop + 37, kText, "%u",
                  static_cast<unsigned>(census_.framesObserved()));

    ui::textAt(6, kBodyTop + 50, kMuted, "crc fail");
    ui::textRight(96, kBodyTop + 50, kFaint, "%u",
                  static_cast<unsigned>(radio_.stats().crcErrors));

    ui::textAt(6, kBodyTop + 63, kMuted, "other rf");
    ui::textRight(96, kBodyTop + 63, kFaint, "%u",
                  static_cast<unsigned>(parseFailures_));

    if (lastLine_[0] != '\0') {
        ui::textAt(6, kBodyTop + 82, kBrass, "%s", lastLine_);
    }

    // The coverage grid, and the number it stands for.
    const uint8_t cols = static_cast<uint8_t>(p.uplinkCount > 8 ? 8 : p.uplinkCount);
    ui::coverageGrid(kGridX, kGridY, cols, p.sfCount(),
                     chIndex_ < cols ? chIndex_ : 0, sfIndex_);

    const int gridBottom = kGridY + p.sfCount() * 5;
    ui::textAt(kGridX, gridBottom + 9, kText, "%u%% heard",
               static_cast<unsigned>(ctx.coveragePercent()));
    ui::textAt(kGridX, gridBottom + 21, kFaint, "of band");

    ui::footer("enter census   h hop   s sf   ` back");
}

void Airspace::drawCensus() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(kInk);

    char right[16];
    std::snprintf(right, sizeof(right), "%u seen", static_cast<unsigned>(census_.size()));
    ui::chrome("Census", right);

    if (census_.size() == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString("Nothing heard yet.", 8, kBodyTop + 8);
        d.setTextColor(kFaint, kInk);
        d.drawString("Uplinks can be minutes apart,", 8, kBodyTop + 28);
        d.drawString("and one radio hears one channel", 8, kBodyTop + 40);
        d.drawString("at a time. Hopping widens it.", 8, kBodyTop + 52);
        ui::footer("` back");
        return;
    }

    const lw::CaptureContext ctx = context();

    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kCensusRows) scroll_ = selected_ - kCensusRows + 1;

    for (int i = 0; i < kCensusRows; i++) {
        const int idx = scroll_ + i;
        if (idx >= static_cast<int>(census_.size())) break;

        const lw::DeviceRecord& rec = census_.at(static_cast<size_t>(idx));
        const auto a = lw::assess(rec, ctx);

        const int y   = kBodyTop + i * kCensusRowH;
        const int mid = y + kCensusRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kCensusRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);

        char label[16];
        if (rec.kind == lw::DeviceKind::Session) {
            std::snprintf(label, sizeof(label), "%08lX",
                          static_cast<unsigned long>(rec.devAddr));
        } else {
            std::snprintf(label, sizeof(label), "%02X%02X%02X%02X*", rec.devEui[4],
                          rec.devEui[5], rec.devEui[6], rec.devEui[7]);
        }

        d.setTextDatum(middle_left);
        d.setTextColor(kText, bg);
        d.drawString(label, 8, mid);

        d.setTextColor(kMuted, bg);
        char sig[20];
        std::snprintf(sig, sizeof(sig), "%ddBm  %ufr", rec.bestRssiDbm,
                      static_cast<unsigned>(rec.framesSeen));
        d.drawString(sig, 86, mid);

        // Grade flush right, with a marker when the evidence under it is thin.
        d.setTextDatum(middle_right);
        d.setTextColor(ui::gradeColour(a.grade), bg);
        d.drawString(lw::gradeName(a.grade), bd::kScreenW - 16, mid);
        if (a.provisional) {
            d.setTextColor(kFaint, bg);
            d.drawString("*", bd::kScreenW - 6, mid);
        }
    }

    d.setTextDatum(top_left);
    ui::footer("enter dossier   ; . move   ` back");
}

void Airspace::drawDossier() {
    auto& d = M5Cardputer.Display;

    if (census_.size() == 0) {
        view_ = View::Census;
        return;
    }
    if (selected_ >= static_cast<int>(census_.size())) selected_ = 0;

    d.fillScreen(kInk);

    const lw::DeviceRecord& rec = census_.at(static_cast<size_t>(selected_));
    const lw::CaptureContext ctx = context();
    const auto a = lw::assess(rec, ctx);

    char title[20];
    if (rec.kind == lw::DeviceKind::Session) {
        std::snprintf(title, sizeof(title), "%08lX",
                      static_cast<unsigned long>(rec.devAddr));
    } else {
        std::snprintf(title, sizeof(title), "%02X%02X%02X%02X", rec.devEui[4],
                      rec.devEui[5], rec.devEui[6], rec.devEui[7]);
    }
    ui::chrome("Dossier", title);

    // The grade, set large in the identity face. The one moment of display type
    // in the whole product, and it earns it.
    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_left);
    d.setTextColor(ui::gradeColour(a.grade), kInk);
    d.drawString(lw::gradeName(a.grade), 8, kBodyTop + 10);

    d.setFont(kFaceData);
    ui::textAt(46, kBodyTop + 5, kMuted, "%u/100  %u frames",
               static_cast<unsigned>(a.score), static_cast<unsigned>(rec.framesSeen));
    if (a.provisional) {
        ui::textAt(46, kBodyTop + 16, kFaint, "provisional: %u%% of band",
                   static_cast<unsigned>(ctx.coveragePercent()));
    }

    int y = kBodyTop + 34;
    if (a.findings.count == 0) {
        ui::textAt(8, y, kGood, "Nothing adverse observed.");
        ui::textAt(8, y + 13, kFaint, "Which is not the same as safe.");
    }

    const int listLimit = bd::kScreenH - kFooterH - 40;
    uint8_t shown = 0;
    for (uint8_t i = 0; i < a.findings.count && y < listLimit; i++) {
        const lw::Finding& f = a.findings.items[i];
        ui::textAt(8, y, ui::severityColour(f.sev), "%s", lw::findingTitle(f.id));

        // Confidence is what stops a finding being an accusation -- but an Info
        // note is a statement about our own capture, not a claim about the
        // device, so a percentage there would be meaningless.
        if (lw::findingCarriesConfidence(f.sev)) {
            ui::textRight(bd::kScreenW - 6, y, kFaint, "%u%%",
                          static_cast<unsigned>(f.confidence));
        }
        y += 12;
        shown++;
    }

    if (shown < a.findings.count) {
        ui::textAt(8, y, kFaint, "+%u more",
                   static_cast<unsigned>(a.findings.count - shown));
        y += 12;
    }

    // The explanation for the most severe finding. Findings are added in
    // severity order, so the first is the one worth the space.
    if (a.findings.count > 0) {
        const int ruleY = bd::kScreenH - kFooterH - 36;
        d.drawFastHLine(6, ruleY, bd::kScreenW - 12, kRule);
        d.setFont(kFaceData);
        ui::wrapText(8, ruleY + 5, bd::kScreenW - 16, 10, 3, kMuted,
                     lw::findingDetail(a.findings.items[0].id));
    }

    d.setTextDatum(top_left);
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
                // Stepping the spreading factor widens coverage but costs dwell
                // time on each -- the real trade the operator is making.
                const lw::ChannelPlan& p = lw::plan(region_);
                sfIndex_ = static_cast<uint8_t>((sfIndex_ + 1) % p.sfCount());
                retune();
                return true;
            }

            case 'r':
                region_ = lw::regionAt(
                    (static_cast<size_t>(region_) + 1) % lw::regionCount());
                chIndex_ = 0;
                sfIndex_ = 0;
                visitedChannels_ = 0;
                visitedSfs_      = 0;
                retune();
                return true;

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
