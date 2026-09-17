#include "wifi_networks.h"

#include <M5Cardputer.h>
#include <WiFi.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace wf = orthrus::wifi;

namespace {

constexpr uint32_t kRedrawMs   = 200;
constexpr uint32_t kRescanMs   = 6000;
constexpr uint32_t kScanGuard  = 15000;  // a scan that never finishes

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';

wf::Security mapSecurity(wifi_auth_mode_t m) {
    switch (m) {
        case WIFI_AUTH_OPEN:            return wf::Security::Open;
        case WIFI_AUTH_WEP:             return wf::Security::Wep;
        case WIFI_AUTH_WPA_PSK:         return wf::Security::WpaPsk;
        case WIFI_AUTH_WPA2_PSK:        return wf::Security::Wpa2Psk;
        case WIFI_AUTH_WPA_WPA2_PSK:    return wf::Security::WpaWpa2Psk;
        case WIFI_AUTH_WPA2_ENTERPRISE: return wf::Security::Wpa2Enterprise;
        case WIFI_AUTH_WPA3_PSK:        return wf::Security::Wpa3Sae;
        case WIFI_AUTH_WPA2_WPA3_PSK:   return wf::Security::Wpa2Wpa3Mixed;
        default:                        return wf::Security::Unknown;
    }
}

// Four bars from RSSI. -55 or better is full, -90 or worse is one.
void signalBars(int x, int y, int16_t rssi, uint16_t colour) {
    auto& d = ui::gfx();
    int bars = 0;
    if (rssi > -60)      bars = 4;
    else if (rssi > -70) bars = 3;
    else if (rssi > -80) bars = 2;
    else                 bars = 1;

    for (int i = 0; i < 4; i++) {
        const int h = 2 + i * 2;
        const int bx = x + i * 3;
        if (i < bars) d.fillRect(bx, y - h, 2, h, colour);
        else          d.drawRect(bx, y - h, 2, h, kRule);
    }
}

}  // namespace

bool WifiNetworks::begin() {
    gnss_.begin();
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
    delay(50);
    return true;
}

int WifiNetworks::findByBssid(const uint8_t bssid[wf::kBssidLen]) const {
    for (uint8_t i = 0; i < count_; i++)
        if (std::memcmp(nets_[i].bssid, bssid, wf::kBssidLen) == 0)
            return static_cast<int>(i);
    return -1;
}

uint8_t WifiNetworks::duplicatesOf(const wf::Network& n) const {
    // A hidden network has no name to duplicate, and counting every unnamed
    // beacon as a twin of every other would flag whole streets.
    if (n.hidden()) return 0;

    uint8_t dup = 0;
    for (uint8_t i = 0; i < count_; i++) {
        if (std::memcmp(nets_[i].bssid, n.bssid, wf::kBssidLen) == 0) continue;
        if (std::strcmp(nets_[i].ssid, n.ssid) == 0) dup++;
    }
    return dup;
}

void WifiNetworks::logNetwork(const wf::Network& n) {
    auto& r = app::recorder();
    if (!r.active()) return;

    char bssid[18];
    wf::formatBssid(n.bssid, bssid);
    const auto a = wf::assess(n, duplicatesOf(n));

    // The SSID goes in last and unquoted: the recorder strips control bytes,
    // and the CSV writer quotes the field, so a hostile name cannot break the
    // log. Spaces in an SSID would confuse the key=value parser though, so it
    // is the final field and read to end of line.
    char detail[96];
    std::snprintf(detail, sizeof(detail), "bssid=%s ch=%u rssi=%d sec=%s grade=%s",
                  bssid, static_cast<unsigned>(n.channel), static_cast<int>(n.rssi),
                  wf::securityName(n.security), wf::gradeName(a.grade));

    const size_t used = std::strlen(detail);
    if (gnss_.hasFix() && used + 32 < sizeof(detail)) {
        std::snprintf(detail + used, sizeof(detail) - used, " lat=%.5f lon=%.5f",
                      gnss_.latitude(), gnss_.longitude());
    }
    r.noteDevice(detail);
}

void WifiNetworks::harvest() {
    const int found = WiFi.scanComplete();
    if (found < 0) return;  // still running, or failed

    newThisScan_ = 0;
    for (int i = 0; i < found && count_ < kMaxNetworks; i++) {
        wf::Network n;
        const String ssid = WiFi.SSID(i);
        std::snprintf(n.ssid, wf::kSsidLen, "%s", ssid.c_str());

        const uint8_t* b = WiFi.BSSID(i);
        if (b) std::memcpy(n.bssid, b, wf::kBssidLen);

        n.channel  = static_cast<uint8_t>(WiFi.channel(i));
        n.rssi     = static_cast<int16_t>(WiFi.RSSI(i));
        n.security = mapSecurity(WiFi.encryptionType(i));

        // Keyed on BSSID, not SSID: one name can legitimately be many radios,
        // and each radio is its own finding.
        const int existing = findByBssid(n.bssid);
        if (existing >= 0) {
            // Keep the strongest reading; that is the one nearest the site.
            if (n.rssi > nets_[existing].rssi) nets_[existing].rssi = n.rssi;
            nets_[existing].security = n.security;
            nets_[existing].channel  = n.channel;
            continue;
        }

        nets_[count_++] = n;
        newThisScan_++;
        logNetwork(n);
    }

    WiFi.scanDelete();
    scanning_ = false;
    sweeps_++;
}

void WifiNetworks::pump() {
    gnss_.pump();

    if (scanning_) {
        harvest();
        // A scan that never completes would otherwise wedge the screen forever.
        if (scanning_ && millis() - scanStarted_ > kScanGuard) {
            WiFi.scanDelete();
            scanning_ = false;
        }
        return;
    }

    if (millis() - scanStarted_ >= kRescanMs) {
        scanStarted_ = millis();
        scanning_    = true;
        // Async, and showing hidden networks: a beacon with an empty SSID is a
        // finding in its own right.
        WiFi.scanNetworks(/*async=*/true, /*show_hidden=*/true);
    }
}

void WifiNetworks::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[24];
    std::snprintf(right, sizeof(right), "%u AP %s", static_cast<unsigned>(count_),
                  scanning_ ? "scan" : "    ");
    ui::chrome("Networks", right);

    if (count_ == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString(scanning_ ? "Scanning 2.4 GHz..." : "No networks yet.",
                     8, kBodyTop + 12);
        d.setTextColor(kFaint, kInk);
        d.drawString("A scan takes a couple of seconds", 8, kBodyTop + 32);
        d.drawString("and repeats on its own.", 8, kBodyTop + 44);
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    if (selected_ >= static_cast<int>(count_)) selected_ = count_ - 1;
    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kRows) scroll_ = selected_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int idx = scroll_ + i;
        if (idx >= static_cast<int>(count_)) break;

        const wf::Network& n = nets_[idx];
        const auto a = wf::assess(n, duplicatesOf(n));

        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        // A hidden network gets a name that says what it is, rather than a gap.
        char label[22];
        if (n.hidden()) std::snprintf(label, sizeof(label), "(hidden)");
        else            std::snprintf(label, sizeof(label), "%.20s", n.ssid);

        d.setTextColor(n.hidden() ? kMuted : kText, bg);
        d.drawString(label, 8, mid);

        d.setTextColor(kMuted, bg);
        d.drawString(wf::securityName(n.security), 122, mid);

        signalBars(184, mid + 4, n.rssi, sel ? kShine : kBrass);

        d.setTextDatum(middle_right);
        d.setTextColor(ui::gradeColour(a.grade), bg);
        d.drawString(wf::gradeName(a.grade), bd::kScreenW - 6, mid);
    }

    d.setTextDatum(top_left);
    ui::footer("enter detail  ; . move  ` back");
    ui::endFrame();
}

void WifiNetworks::drawDossier() {
    if (count_ == 0 || selected_ < 0 || selected_ >= static_cast<int>(count_)) {
        view_ = View::List;
        return;
    }

    ui::beginFrame();
    auto& d = ui::gfx();

    const wf::Network& n = nets_[selected_];
    const uint8_t dup = duplicatesOf(n);
    const auto a = wf::assess(n, dup);

    ui::chrome("Network", n.hidden() ? "(hidden)" : n.ssid);

    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_left);
    d.setTextColor(ui::gradeColour(a.grade), kInk);
    d.drawString(wf::gradeName(a.grade), 8, kBodyTop + 12);

    d.setFont(kFaceData);
    ui::textAt(46, kBodyTop + 5, kText, "%s", wf::securityName(n.security));
    ui::textAt(46, kBodyTop + 17, kMuted, "ch %u   %d dBm",
               static_cast<unsigned>(n.channel), static_cast<int>(n.rssi));
    ui::textRight(bd::kScreenW - 6, kBodyTop + 5, kFaint, "%u/100",
                  static_cast<unsigned>(a.score));

    char bssid[18];
    wf::formatBssid(n.bssid, bssid);
    ui::textRight(bd::kScreenW - 6, kBodyTop + 17, kFaint, "%s", bssid);

    d.drawFastHLine(6, kBodyTop + 28, bd::kScreenW - 12, kRule);

    int y = kBodyTop + 38;
    const int listLimit = bd::kScreenH - kFooterH - 38;
    uint8_t shown = 0;
    for (uint8_t i = 0; i < a.findings.count && y < listLimit; i++) {
        const wf::Finding& f = a.findings.items[i];
        ui::textAt(8, y, ui::severityColour(f.sev), "%s", wf::findingTitle(f.id));
        if (wf::findingCarriesConfidence(f.sev)) {
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

    if (a.findings.count > 0) {
        const int ruleY = bd::kScreenH - kFooterH - 34;
        d.drawFastHLine(6, ruleY, bd::kScreenW - 12, kRule);
        d.setFont(kFaceData);
        ui::wrapText(8, ruleY + 4, bd::kScreenW - 16, 10, 3, kMuted,
                     wf::findingDetail(a.findings.items[0].id));
    }

    d.setTextDatum(top_left);
    ui::footer("; . network   ` back");
    ui::endFrame();
}

bool WifiNetworks::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (ks.enter) {
        if (view_ == View::List && count_) view_ = View::Dossier;
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Dossier) { view_ = View::List; return true; }
                return false;
            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;
            case kKeyDown:
                if (selected_ + 1 < static_cast<int>(count_)) selected_++;
                return true;
            default:
                break;
        }
    }
    return true;
}

void WifiNetworks::run() {
    scanStarted_ = millis() - kRescanMs;  // scan immediately on entry

    for (;;) {
        M5Cardputer.update();
        pump();

        if (!handleKeys()) {
            // Leave the radio off. Wi-Fi is the most expensive thing on this
            // board and the operator has walked away from the screen.
            WiFi.scanDelete();
            WiFi.mode(WIFI_OFF);
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            if (view_ == View::List) drawList();
            else                     drawDossier();
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
