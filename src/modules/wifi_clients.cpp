#include "wifi_clients.h"

#include <M5Cardputer.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "dot11/frame.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd  = orthrus::board;
namespace d11 = orthrus::dot11;

namespace {

constexpr uint32_t kRedrawMs = 200;
constexpr uint32_t kDwellMs  = 400;
constexpr uint8_t  kMaxChannel = 13;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp     = ';';
constexpr char kKeyDown   = '.';
constexpr char kKeyBack   = '`';
constexpr char kKeyLock   = 'l';
constexpr char kKeyFilter = 'f';

// ---- the ring between the Wi-Fi task and the UI loop ------------------------

constexpr uint16_t kSlotBytes = 192;   // a probe request is small
constexpr uint8_t  kSlots     = 12;

struct Slot {
    uint16_t len = 0;
    int8_t   rssi = 0;
    uint8_t  data[kSlotBytes] = {0};
};

Slot              g_ring[kSlots];
volatile uint8_t  g_head = 0;
volatile uint8_t  g_tail = 0;
volatile uint32_t g_frames = 0;
volatile uint32_t g_overruns = 0;

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (buf == nullptr) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* frame = pkt->payload;
    const uint16_t len   = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    d11::FrameInfo fi;
    if (!d11::parseHeader(frame, len, fi)) return;

    // Only two things are interesting: a probe request (which may name a
    // network) and an uplink data frame (which proves a device is associated).
    // Beacons are the access points themselves and belong on another screen.
    bool want = false;
    if (fi.type == d11::FrameType::Management &&
        fi.subtype == d11::kSubtypeProbeReq) {
        want = true;
    } else if (fi.type == d11::FrameType::Data && fi.toDs && !fi.fromDs) {
        want = true;
    }
    if (!want) return;

    g_frames++;

    const uint8_t next = static_cast<uint8_t>((g_head + 1) % kSlots);
    if (next == g_tail) {
        g_overruns++;
        return;
    }
    uint16_t n = len;
    if (n > kSlotBytes) n = kSlotBytes;
    std::memcpy(g_ring[g_head].data, frame, n);
    g_ring[g_head].len  = n;
    g_ring[g_head].rssi = static_cast<int8_t>(pkt->rx_ctrl.rssi);
    g_head = next;
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

bool WifiClients::begin() {
    table_.clear();
    g_head = g_tail = 0;
    g_frames = g_overruns = 0;
    probesSeen_ = namedSeen_ = 0;
    enteredMs_ = millis();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
    delay(50);

    // Two steps Arduino's WiFi.mode() does not do for us, and both matter for a
    // sniffer:
    //
    //   esp_wifi_set_ps(WIFI_PS_NONE) -- the STA_START handler turns on
    //   WIFI_PS_MIN_MODEM, so the radio periodically SLEEPS. A sleeping radio
    //   misses frames, and it misses them silently: the capture just looks
    //   thin. Nothing else in this firmware turns it back off.
    //
    //   esp_wifi_set_storage(WIFI_STORAGE_RAM) -- otherwise every mode change
    //   is written to NVS, wearing flash for settings we never want persisted.
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) return false;

    channel_   = 1;
    lastHopMs_ = millis();
    esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
    return true;
}

void WifiClients::hop() {
    if (locked_) return;
    if (millis() - lastHopMs_ < kDwellMs) return;
    lastHopMs_ = millis();
    channel_ = static_cast<uint8_t>(channel_ % kMaxChannel + 1);
    esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
}

void WifiClients::drain() {
    for (int budget = 0; budget < 8; budget++) {
        if (g_tail == g_head) return;
        const Slot& s = g_ring[g_tail];

        d11::FrameInfo fi;
        if (d11::parseHeader(s.data, s.len, fi)) {
            if (fi.type == d11::FrameType::Management) {
                // A probe request's body is tagged elements with no fixed
                // parameters in front of them -- unlike a beacon, which has
                // twelve bytes of timestamp and capability first. Feeding it to
                // the beacon parser would skip the SSID element entirely.
                const uint8_t* body = s.data + fi.headerLen;
                const size_t bodyLen = s.len - fi.headerLen;

                char ssid[d11::kSsidBuf] = {0};
                if (bodyLen >= 2 && body[0] == 0x00) {
                    size_t n = body[1];
                    if (n > d11::kSsidMax) n = d11::kSsidMax;
                    if (2 + n <= bodyLen) {
                        std::memcpy(ssid, body + 2, n);
                        ssid[n] = '\0';
                        // A NUL-padded SSID is a broadcast probe wearing a
                        // length, and means the same as an empty one.
                        bool allNul = true;
                        for (size_t k = 0; k < n; k++)
                            if (ssid[k] != '\0') { allNul = false; break; }
                        if (allNul) ssid[0] = '\0';

                        // Control bytes in a name would corrupt any line it is
                        // written to, including the evidence log.
                        for (size_t k = 0; ssid[k]; k++) {
                            const unsigned char c =
                                static_cast<unsigned char>(ssid[k]);
                            if (c < 0x20 || c == 0x7F) ssid[k] = ' ';
                        }
                    }
                }

                probesSeen_++;
                if (ssid[0]) namedSeen_++;
                table_.noteProbe(fi.addr2, ssid, s.rssi, millis());
            } else if (fi.type == d11::FrameType::Data) {
                uint8_t bssid[d11::kMacLen], sta[d11::kMacLen];
                if (d11::resolveEndpoints(fi, bssid, sta))
                    table_.noteAssociation(sta, bssid, s.rssi, millis());
            }
        }

        g_tail = static_cast<uint8_t>((g_tail + 1) % kSlots);
    }
}

void WifiClients::pump() {
    hop();
    drain();
}

int WifiClients::visibleCount() const {
    if (!talkersOnly_) return table_.count();
    int n = 0;
    for (uint8_t i = 0; i < table_.count(); i++)
        if (table_.at(i).hasNamedProbes()) n++;
    return n;
}

int WifiClients::visibleAt(int i) const {
    if (!talkersOnly_) return i;
    int n = 0;
    for (uint8_t k = 0; k < table_.count(); k++) {
        if (!table_.at(k).hasNamedProbes()) continue;
        if (n == i) return static_cast<int>(k);
        n++;
    }
    return -1;
}

// ---- screens -----------------------------------------------------------------

void WifiClients::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const int visible = visibleCount();

    char right[24];
    std::snprintf(right, sizeof(right), "ch%u%s %d", static_cast<unsigned>(channel_),
                  locked_ ? "*" : "", visible);
    ui::chrome("Clients", right);

    if (visible == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString(talkersOnly_ ? "No named probes yet." : "Listening...", 8,
                     kBodyTop + 6);
        ui::wrapText(8, kBodyTop + 22, bd::kScreenW - 16, 10, 4, kFaint,
                     "Passive: nothing is transmitted. Devices probe every few "
                     "seconds, but most probes name no network at all.");
        ui::textAt(8, bd::kScreenH - kFooterH - 10, kFaint, "%lu frames  %lu probes",
                   static_cast<unsigned long>(g_frames),
                   static_cast<unsigned long>(probesSeen_));
        ui::footer("l lock   f filter   ` back");
        ui::endFrame();
        return;
    }

    if (selected_ >= visible) selected_ = visible - 1;
    if (selected_ < 0) selected_ = 0;
    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kRows) scroll_ = selected_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int vis = scroll_ + i;
        if (vis >= visible) break;
        const int idx = visibleAt(vis);
        if (idx < 0) break;

        const d11::Station& st = table_.at(idx);
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (vis == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        char label[20];
        std::snprintf(label, sizeof(label), "%02x%02x%02x", st.mac[3], st.mac[4],
                      st.mac[5]);
        d.setTextColor(kText, bg);
        d.drawString(label, 8, mid);

        // The one word that decides whether this row is a device or a disguise.
        d.setTextColor(st.randomised ? kFaint : kBrass, bg);
        d.drawString(st.randomised ? "random" : "real", 48, mid);

        if (st.hasNamedProbes()) {
            d.setTextColor(kShine, bg);
            char probe[20];
            std::snprintf(probe, sizeof(probe), "%.14s", st.ssids[0]);
            d.drawString(probe, 96, mid);
        } else if (st.associated) {
            d.setTextColor(kMuted, bg);
            d.drawString("associated", 96, mid);
        }

        signalBars(bd::kScreenW - 20, mid + 4, st.rssi, sel ? kShine : kBrass);
    }

    d.setTextDatum(top_left);
    ui::footer("enter  l lock  f filter  ` back");
    ui::endFrame();
}

void WifiClients::drawDetail() {
    const int visible = visibleCount();
    if (visible == 0) {
        view_ = View::List;
        return;
    }
    if (selected_ >= visible) selected_ = visible - 1;
    const int idx = visibleAt(selected_);
    if (idx < 0) {
        view_ = View::List;
        return;
    }

    ui::beginFrame();
    auto& d = ui::gfx();
    const d11::Station& st = table_.at(idx);

    ui::chrome("Device", st.randomised ? "randomised" : "real address");

    d.setFont(kFaceData);
    char mac[18];
    d11::formatMacColons(st.mac, mac);
    ui::textAt(8, kBodyTop + 5, kText, "%s", mac);
    ui::textRight(bd::kScreenW - 6, kBodyTop + 5, kFaint, "%d dBm",
                  static_cast<int>(st.rssi));

    if (st.associated) {
        char ap[18];
        d11::formatMacColons(st.bssid, ap);
        ui::textAt(8, kBodyTop + 17, kMuted, "on %s", ap);
    } else {
        ui::textAt(8, kBodyTop + 17, kFaint, "not associated here");
    }

    d.drawFastHLine(6, kBodyTop + 27, bd::kScreenW - 12, kRule);

    if (st.hasNamedProbes()) {
        ui::textAt(8, kBodyTop + 35, kBrass, "looking for:");
        int y = kBodyTop + 47;
        for (uint8_t i = 0; i < st.ssidCount && i < 3; i++) {
            ui::textAt(14, y, kShine, "%.30s", st.ssids[i]);
            y += 11;
        }
        ui::wrapText(8, bd::kScreenH - kFooterH - 22, bd::kScreenW - 16, 10, 2,
                     kFaint,
                     "It will join anything answering to these names.");
    } else {
        ui::textAt(8, kBodyTop + 35, kMuted, "%lu probes, none named",
                   static_cast<unsigned long>(st.probes));
        ui::wrapText(8, kBodyTop + 48, bd::kScreenW - 16, 10, 4, kFaint,
                     "Modern phones send broadcast probes that name nothing. "
                     "That is the device behaving well, not a failed capture.");
    }

    d.setTextDatum(top_left);
    ui::footer("; . device   ` back");
    ui::endFrame();
}

bool WifiClients::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (ks.enter) {
        if (view_ == View::List && visibleCount()) view_ = View::Detail;
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Detail) { view_ = View::List; return true; }
                return false;
            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;
            case kKeyDown:
                if (selected_ + 1 < visibleCount()) selected_++;
                return true;
            case kKeyLock:
                locked_ = !locked_;
                return true;
            case kKeyFilter:
                talkersOnly_ = !talkersOnly_;
                selected_ = scroll_ = 0;
                return true;
            default:
                break;
        }
    }
    return true;
}

void WifiClients::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        pump();

        if (!handleKeys()) {
            // Log the summary on the way out rather than a record per device:
            // an engagement wants "twelve devices, four naming networks", not
            // two hundred sightings.
            if (table_.count()) {
                char detail[96];
                std::snprintf(detail, sizeof(detail),
                              "clients seen=%u named=%u probes=%lu randomised=%u",
                              static_cast<unsigned>(table_.count()),
                              static_cast<unsigned>(table_.talkers()),
                              static_cast<unsigned long>(probesSeen_),
                              [&] {
                                  unsigned r = 0;
                                  for (uint8_t i = 0; i < table_.count(); i++)
                                      if (table_.at(i).randomised) r++;
                                  return r;
                              }());
                app::recorder().noteFinding(detail);
            }
            esp_wifi_set_promiscuous(false);
            WiFi.mode(WIFI_OFF);
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            if (view_ == View::List) drawList();
            else                     drawDetail();
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
