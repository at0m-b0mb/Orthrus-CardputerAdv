#include "airspace.h"

#include <M5Cardputer.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"
#include "lorawan/findings.h"
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
constexpr int kGridX      = 168;
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
    gnss_.begin();
    for (uint8_t i = 0; i < kTraceLen; i++) rssiTrace_[i] = -120;

    // Re-entering the module must not reset the clock, or every return trip
    // would make a long capture look like it had only just started -- and
    // listenedMs feeds the confidence given to absence-based findings.
    if (startedMs_ == 0) {
        startedMs_ = millis();
        lastHopMs_ = startedMs_;
    }
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

void Airspace::logDevice(const lw::DeviceRecord& rec, const lw::RxMeta& meta) {
    auto& r = app::recorder();
    if (!r.active()) return;

    char label[20];
    if (rec.kind == lw::DeviceKind::Session) {
        std::snprintf(label, sizeof(label), "%08lX",
                      static_cast<unsigned long>(rec.devAddr));
    } else {
        std::snprintf(label, sizeof(label), "%02X%02X%02X%02X", rec.devEui[4],
                      rec.devEui[5], rec.devEui[6], rec.devEui[7]);
    }

    const auto a = lw::assess(rec, context());

    char detail[96];
    int n = std::snprintf(detail, sizeof(detail),
                          "dev=%s rssi=%d sf=%u grade=%s", label,
                          static_cast<int>(meta.rssiDbm),
                          static_cast<unsigned>(meta.sf), lw::gradeName(a.grade));

    // Position only when there is a real fix. A sighting without one is still
    // worth logging; it simply cannot be placed on a map.
    if (gnss_.hasFix() && n > 0 && n < static_cast<int>(sizeof(detail))) {
        std::snprintf(detail + n, sizeof(detail) - n, " lat=%.5f lon=%.5f",
                      gnss_.latitude(), gnss_.longitude());
    }
    r.noteDevice(detail);
}

void Airspace::sampleRssi() {
    if (millis() - lastRssiMs_ < 60) return;
    lastRssiMs_ = millis();

    // Instantaneous, taken while the modem is in receive. This is the number
    // that proves to the operator that the radio is listening even when the
    // band is silent.
    const float v = radio_.instantRssi();
    if (v == 0.0f) return;
    rssiNow_ = v;

    int8_t clamped = static_cast<int8_t>(v < -128 ? -128 : (v > -20 ? -20 : v));
    rssiTrace_[rssiPos_] = clamped;
    rssiPos_ = static_cast<uint8_t>((rssiPos_ + 1) % kTraceLen);
    if (rssiPos_ == 0) traceFull_ = true;
}

void Airspace::pump() {
    gnss_.pump();
    sampleRssi();

    static uint8_t phy[kMaxPhyLen];
    lw::RxMeta meta;

    const int len = radio_.poll(phy, sizeof(phy), meta);
    if (len > 0) {
        lw::Frame f;
        if (lw::parse(phy, static_cast<size_t>(len), f)) {
            const size_t before = census_.size();
            const int idx = census_.observe(f, meta);
            lastFrameMs_ = millis();

            // Log the first sighting only. Every uplink from a chatty sensor
            // would otherwise fill the card with the same line.
            if (idx >= 0 && census_.size() > before) logDevice(census_.at(static_cast<size_t>(idx)), meta);

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
    ui::beginFrame();
    auto& d = ui::gfx();
    const lw::ChannelPlan& p = lw::plan(region_);
    const lw::CaptureContext ctx = context();

    char right[20];
    std::snprintf(right, sizeof(right), "%s %s", p.name, hopping_ ? "HOP" : "PARK");
    ui::chrome("Airspace", right);

    d.setFont(kFaceData);

    // Tuning, in the accent: the one thing that changes as you hop.
    ui::textAt(6, kBodyTop + 4, kShine, "%.3f MHz  SF%u",
               p.uplinkHz[chIndex_] / 1e6,
               static_cast<unsigned>(p.sfMin + sfIndex_));

    // A countdown to the next hop, so the dwell is visible rather than a
    // mystery pause.
    if (hopping_) {
        const uint32_t elapsed = millis() - lastHopMs_;
        const int barW = 56;
        const int fill = hopDwellMs_ ? static_cast<int>((elapsed * barW) / hopDwellMs_) : 0;
        d.drawRect(kGridX, kBodyTop, barW, 4, kRule);
        if (fill > 0) d.fillRect(kGridX, kBodyTop, fill > barW ? barW : fill, 4, kBrass);
    }

    // ---- the live floor trace: always moving, traffic or not ---------------
    constexpr int kTraceX = 6, kTraceY = kBodyTop + 14, kTraceH = 20;
    d.drawFastHLine(kTraceX, kTraceY + kTraceH, kTraceLen * 2, kRule);

    const int span = 100;  // -120 .. -20 dBm
    const uint8_t count = traceFull_ ? kTraceLen : rssiPos_;
    for (uint8_t i = 0; i < count; i++) {
        const uint8_t idx = traceFull_
            ? static_cast<uint8_t>((rssiPos_ + i) % kTraceLen)
            : i;
        int h = ((rssiTrace_[idx] + 120) * kTraceH) / span;
        if (h < 1) h = 1;
        if (h > kTraceH) h = kTraceH;
        d.fillRect(kTraceX + i * 2, kTraceY + kTraceH - h, 2, h, kBrass);
    }
    ui::textRight(bd::kScreenW - 6, kTraceY + 8, kText, "%d dBm",
                  static_cast<int>(rssiNow_));

    // ---- counters ----------------------------------------------------------
    ui::textAt(6, kBodyTop + 46, kMuted, "dev");
    ui::textAt(34, kBodyTop + 46, kText, "%u", static_cast<unsigned>(census_.size()));
    ui::textAt(62, kBodyTop + 46, kMuted, "frm");
    ui::textAt(92, kBodyTop + 46, kText, "%u",
               static_cast<unsigned>(census_.framesObserved()));
    ui::textRight(bd::kScreenW - 6, kBodyTop + 46, kFaint, "%u%% band",
                  static_cast<unsigned>(ctx.coveragePercent()));

    ui::textAt(6, kBodyTop + 58, kMuted, "crc");
    ui::textAt(34, kBodyTop + 58, kFaint, "%u",
               static_cast<unsigned>(radio_.stats().crcErrors));
    ui::textAt(62, kBodyTop + 58, kMuted, "oth");
    ui::textAt(92, kBodyTop + 58, kFaint, "%u",
               static_cast<unsigned>(parseFailures_));

    // ---- GPS: real data, arriving once a second, fix or no fix -------------
    if (!gnss_.alive()) {
        ui::textAt(6, kBodyTop + 72, kFaint, "GPS  no data");
    } else if (gnss_.hasFix()) {
        ui::textAt(6, kBodyTop + 72, kGood, "GPS %.4f,%.4f",
                   gnss_.latitude(), gnss_.longitude());
    } else {
        // Satellites-in-view climbs long before a fix lands, so this line moves
        // even indoors -- which is the whole point.
        ui::textAt(6, kBodyTop + 72, kBrass, "GPS searching  %lu sats  %lu msg",
                   static_cast<unsigned long>(gnss_.satellites()),
                   static_cast<unsigned long>(gnss_.sentences()));
    }

    if (lastLine_[0] != '\0') {
        ui::textAt(6, kBodyTop + 84, kText, "%s", lastLine_);
    }

    ui::footer("enter list  h hop  s sf  x sweep  ` back");
    ui::endFrame();
}

void Airspace::drawCensus() {
    ui::beginFrame();
    auto& d = ui::gfx();

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
        ui::endFrame();
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
    ui::footer("enter open  ; . move  c clear  ` back");
    ui::endFrame();
}

void Airspace::drawDossier() {
    if (census_.size() == 0) {
        view_ = View::Census;
        return;
    }
    if (selected_ >= static_cast<int>(census_.size())) selected_ = 0;

    ui::beginFrame();
    auto& d = ui::gfx();

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
    ui::endFrame();
}

void Airspace::drawSpectrum() {
    ui::beginFrame();
    const lw::ChannelPlan& p = lw::plan(region_);

    char right[20];
    std::snprintf(right, sizeof(right), "%s sweep %lu", p.name,
                  static_cast<unsigned long>(spectrum_.sweeps()));
    ui::chrome("Spectrum", right);

    constexpr int kGraphX = 4, kGraphY = 22, kGraphH = 68;
    const int graphW = Spectrum::kBins * 2;
    spectrum_.draw(kGraphX, kGraphY, graphW, kGraphH);

    // Axis ends, so the trace means something without counting pixels.
    ui::textAt(kGraphX, kGraphY + kGraphH + 9, kFaint, "%.0f",
               spectrum_.startHz() / 1e6);
    ui::textRight(kGraphX + graphW, kGraphY + kGraphH + 9, kFaint, "%.0f MHz",
                  spectrum_.endHz() / 1e6);

    if (spectrum_.hasData()) {
        const int peak = spectrum_.peakBin();
        ui::textAt(kGraphX, kGraphY + kGraphH + 22, kShine, "peak %.2f MHz  %d dBm",
                   spectrum_.binFreqHz(peak) / 1e6,
                   static_cast<int>(spectrum_.hold(peak)));
    } else {
        ui::textAt(kGraphX, kGraphY + kGraphH + 22, kMuted, "sweeping...");
    }

    // The radio cannot listen for frames and sweep at the same time. Saying so
    // is better than letting an operator believe the capture is still running.
    ui::footer("capture paused   m max-hold   ` back");
    ui::endFrame();
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
                else if (view_ == View::Spectrum) {
                    // The sweep left the radio wherever it last looked.
                    view_ = View::Live;
                    retune();
                } else return false;  // leave the module
                return true;

            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (selected_ + 1 < static_cast<int>(census_.size())) selected_++;
                return true;

            case 'x': {
                const lw::ChannelPlan& p = lw::plan(region_);
                spectrum_.configure(p.spectrumStartHz, p.spectrumEndHz);
                view_ = View::Spectrum;
                return true;
            }

            case 'm':
                if (view_ == View::Spectrum) spectrum_.reset();
                return true;

            case 'h':
                hopping_ = !hopping_;
                lastHopMs_ = millis();
                return true;

            case 'c':
                // Start a fresh capture. A survey tool with no way to clear the
                // table forces an operator to power-cycle between sites, which
                // also loses the coverage they had built up.
                if (view_ == View::Census) {
                    census_.reset();
                    selected_        = 0;
                    scroll_          = 0;
                    parseFailures_   = 0;
                    startedMs_       = millis();
                    lastLine_[0]     = '\0';
                    visitedChannels_ = 0;
                    visitedSfs_      = 0;
                    retune();  // re-mark the channel we are actually on
                }
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
                // Devices heard under the old plan cannot be graded against the
                // new plan's coverage, so the capture starts over with it.
                census_.reset();
                selected_ = 0;
                scroll_   = 0;
                startedMs_ = millis();
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

        // The radio serves exactly one job at a time. Sweeping retunes it away
        // from the capture channel, so the two cannot overlap.
        if (view_ == View::Spectrum) spectrum_.step(radio_);
        else                         pump();

        if (!handleKeys()) {
            radio_.idle();  // do not leave the receiver running behind us
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Live:    drawLive();    break;
                case View::Census:  drawCensus();  break;
                case View::Dossier: drawDossier(); break;
                case View::Spectrum: drawSpectrum(); break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
