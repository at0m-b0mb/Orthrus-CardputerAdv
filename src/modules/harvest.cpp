#include "harvest.h"

#include <M5Cardputer.h>
#include <SD.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "dot11/hashline.h"
#include "hal/board.h"
#include "hal/lora_radio.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace d11 = orthrus::dot11;

namespace {

constexpr uint32_t kRedrawMs = 180;

// Dwell per channel. A four-way handshake is over in tens of milliseconds, so
// dwell time is the whole game: too short and you sweep past every one of them.
constexpr uint32_t kDwellMs      = 450;
// Channels 1, 6 and 11 do not overlap, which is why almost every access point
// is on one of them. They get three times the dwell; the rest are swept so that
// a network parked on channel 3 is not invisible.
constexpr uint32_t kBusyDwellMs  = 1350;
constexpr uint8_t  kMaxChannel   = 13;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyBack  = '`';
constexpr char kKeyLock  = 'l';
constexpr char kKeySave  = 's';

bool isBusyChannel(uint8_t ch) { return ch == 1 || ch == 6 || ch == 11; }

// ---- the ring between the Wi-Fi task and the UI loop ------------------------
//
// The promiscuous callback runs inside the Wi-Fi driver's own task. Touching
// the SD card or the display from there would block the radio; so would the
// ~7 KB target table's bookkeeping. The callback does the smallest amount of
// work that lets it decide whether a frame matters, copies it, and returns.

constexpr uint16_t kSlotBytes = 384;
constexpr uint8_t  kSlots     = 10;

struct Slot {
    uint16_t len     = 0;
    uint16_t origLen = 0;
    uint8_t  channel = 0;
    int8_t   rssi    = 0;
    uint8_t  data[kSlotBytes] = {0};
};

Slot              g_ring[kSlots];
volatile uint8_t  g_head = 0;   // written by the Wi-Fi task
volatile uint8_t  g_tail = 0;   // written by the UI loop
volatile uint32_t g_overruns = 0;
volatile uint32_t g_seen     = 0;
uint32_t          g_lastBeaconMs = 0;

uint8_t ringUsed() {
    const uint8_t h = g_head, t = g_tail;
    return static_cast<uint8_t>((h + kSlots - t) % kSlots);
}

// Returns false when the ring is full. One producer, one consumer, so the
// indices need no lock -- only the discipline that each side writes exactly one
// of them.
bool ringPush(const uint8_t* frame, uint16_t len, uint16_t origLen, uint8_t channel,
              int8_t rssi) {
    const uint8_t h    = g_head;
    const uint8_t next = static_cast<uint8_t>((h + 1) % kSlots);
    if (next == g_tail) {
        g_overruns++;
        return false;
    }
    if (len > kSlotBytes) len = kSlotBytes;
    std::memcpy(g_ring[h].data, frame, len);
    g_ring[h].len     = len;
    g_ring[h].origLen = origLen;
    g_ring[h].channel = channel;
    g_ring[h].rssi    = rssi;
    g_head = next;
    return true;
}

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (buf == nullptr) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* frame = pkt->payload;
    const uint16_t len   = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    g_seen++;

    d11::FrameInfo fi;
    if (!d11::parseHeader(frame, len, fi)) return;

    const uint8_t ch   = static_cast<uint8_t>(pkt->rx_ctrl.channel);
    const int8_t  rssi = static_cast<int8_t>(pkt->rx_ctrl.rssi);

    if (fi.type == d11::FrameType::Data) {
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        if (!d11::eapolPayload(frame, len, fi, &payload, &payloadLen)) return;
        // EAPOL is rare and precious. It is never throttled and never yields
        // its place in the ring to a beacon.
        ringPush(frame, len, len, ch, rssi);
        return;
    }

    if (fi.subtype != d11::kSubtypeBeacon && fi.subtype != d11::kSubtypeProbeResp)
        return;

    // Beacons arrive ten times a second from every access point in range and
    // would swamp the ring within a second, pushing out the one frame that
    // matters. Two brakes: a time throttle, and a hard rule that a beacon may
    // only use the ring while it is less than half empty.
    const uint32_t now = millis();
    if (now - g_lastBeaconMs < 40) return;
    if (ringUsed() > kSlots / 2) return;
    g_lastBeaconMs = now;
    ringPush(frame, len, len, ch, rssi);
}

// Four bars from RSSI, matching Perimeter so the two Wi-Fi surfaces read alike.
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

uint16_t qualityColour(d11::Quality q) {
    switch (q) {
        case d11::Quality::Both:      return kGood;
        case d11::Quality::Handshake: return kGood;
        case d11::Quality::Pmkid:     return kMedium;
        case d11::Quality::Fragment:  return kFaint;
        case d11::Quality::Nothing:   return kFaint;
    }
    return kFaint;
}

}  // namespace

bool Harvest::begin() {
    table_.clear();
    g_head = g_tail = 0;
    g_overruns = 0;
    g_seen = 0;

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
    delay(50);

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

void Harvest::hop() {
    if (locked_) return;

    const uint32_t dwell = isBusyChannel(channel_) ? kBusyDwellMs : kDwellMs;
    if (millis() - lastHopMs_ < dwell) return;

    lastHopMs_ = millis();
    channel_ = static_cast<uint8_t>(channel_ % kMaxChannel + 1);
    esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
}

void Harvest::handleBeacon(const uint8_t* frame, uint16_t len,
                           const d11::FrameInfo& fi, uint8_t channel, int8_t rssi) {
    d11::BeaconInfo b;
    if (!d11::parseBeacon(frame + fi.headerLen, len - fi.headerLen, b)) return;

    beaconsSeen_++;

    // addr3 is the BSSID on a management frame. addr2 is the same radio here,
    // but addr3 is the field that is defined to carry it.
    const uint8_t* bssid = fi.addr3;

    // A beacon's own DS Parameter Set beats the channel we happened to be tuned
    // to; fall back to ours when the element is absent.
    const uint8_t apChannel = b.channel ? b.channel : channel;

    table_.noteBeacon(bssid, b.ssid, apChannel, rssi);

    // One beacon per network into the capture file, and only once the file is
    // open -- which it is not until something worth capturing has arrived. That
    // ordering is deliberate: opening a pcap the moment the screen is entered
    // would litter the card with empty captures from anyone who just looked.
    if (pcapOpen_ && !beaconAlreadyWritten(bssid)) writePcapFrame(frame, len);
}

bool Harvest::beaconAlreadyWritten(const uint8_t bssid[d11::kMacLen]) {
    for (uint8_t i = 0; i < beaconWrittenCount_; i++)
        if (std::memcmp(beaconWritten_[i], bssid, d11::kMacLen) == 0) return true;

    // Once the list is full, later networks simply do not get a beacon written.
    // Their handshakes are still captured and their names are still in the
    // hash file, which is the artefact that matters.
    if (beaconWrittenCount_ < kMaxNamedBeacons) {
        std::memcpy(beaconWritten_[beaconWrittenCount_++], bssid, d11::kMacLen);
    }
    return false;
}

void Harvest::handleData(const uint8_t* frame, uint16_t len,
                         const d11::FrameInfo& fi, uint8_t channel, int8_t rssi) {
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (!d11::eapolPayload(frame, len, fi, &payload, &payloadLen)) return;

    d11::KeyFrame kf;
    if (!d11::parseKeyFrame(payload, payloadLen, kf)) return;
    if (kf.message == d11::Message::Unknown) return;

    uint8_t bssid[d11::kMacLen], sta[d11::kMacLen];
    if (!d11::resolveEndpoints(fi, bssid, sta)) return;

    eapolSeen_++;

    // What we held before this frame, so the log can record the step UP rather
    // than the frame.
    d11::Quality wasQuality = d11::Quality::Nothing;
    for (uint8_t i = 0; i < table_.count(); i++) {
        if (d11::macEqual(table_.at(i).bssid, bssid) &&
            d11::macEqual(table_.at(i).sta, sta)) {
            wasQuality = table_.at(i).quality();
            break;
        }
    }

    const d11::Target* t =
        table_.ingest(bssid, sta, kf, payload, payloadLen, channel, rssi, millis());
    if (t == nullptr) return;

    writePcapFrame(frame, len);

    // One evidence record per step UP in quality, not one per frame. A busy
    // network retransmits M3 half a dozen times and the log would say nothing
    // six times over.
    const d11::Quality now = t->quality();
    if (now > wasQuality && now >= d11::Quality::Pmkid) {
        char ap[18];
        d11::formatMacColons(t->bssid, ap);
        char detail[96];
        std::snprintf(detail, sizeof(detail),
                      "wpa bssid=%s ch=%u have=%s ssid=%s", ap,
                      static_cast<unsigned>(t->channel), d11::qualityName(now),
                      t->named() ? t->ssid : "(unknown)");
        app::recorder().noteFinding(detail);
    }
}

void Harvest::drain() {
    // Bounded per call so a burst cannot starve the UI: the loop redraws at
    // about five frames a second and must keep doing so.
    for (int budget = 0; budget < 6; budget++) {
        if (g_tail == g_head) return;

        const Slot& s = g_ring[g_tail];
        framesSeen_++;

        d11::FrameInfo fi;
        if (d11::parseHeader(s.data, s.len, fi)) {
            if (fi.type == d11::FrameType::Management) {
                handleBeacon(s.data, s.len, fi, s.channel, s.rssi);
            } else if (fi.type == d11::FrameType::Data) {
                handleData(s.data, s.len, fi, s.channel, s.rssi);
            }
        }

        g_tail = static_cast<uint8_t>((g_tail + 1) % kSlots);
    }
}

void Harvest::pump() {
    hop();
    drain();
}

// ---- files ------------------------------------------------------------------

bool Harvest::openPcap() {
    if (pcapOpen_) return true;
    if (pcapFailed_) return false;

    // Mounts the card if nothing has yet. The evidence log and the capture
    // files share one card and one session.
    if (!app::recorder().begin() && !app::recorder().active()) {
        pcapFailed_ = true;
        return false;
    }

    if (!SD.exists("/orthrus")) SD.mkdir("/orthrus");

    // No RTC on this board, so filenames are indexed rather than dated, the
    // same way session logs are.
    for (int i = 1; i < 1000; i++) {
        std::snprintf(pcapPath_, sizeof(pcapPath_), "/orthrus/harvest-%03d.pcap", i);
        std::snprintf(hashPath_, sizeof(hashPath_), "/orthrus/harvest-%03d.22000", i);
        if (!SD.exists(pcapPath_) && !SD.exists(hashPath_)) break;
        pcapPath_[0] = '\0';
    }
    if (pcapPath_[0] == '\0') {
        pcapFailed_ = true;
        return false;
    }

    pcap_ = SD.open(pcapPath_, FILE_WRITE);
    if (!pcap_) {
        pcapFailed_ = true;
        return false;
    }

    uint8_t header[d11::kPcapGlobalHeaderLen];
    const size_t n = d11::writePcapGlobalHeader(header, sizeof(header), kSlotBytes);
    if (pcap_.write(header, n) != n) {
        pcap_.close();
        pcapFailed_ = true;
        return false;
    }

    pcapOpen_ = true;
    return true;
}

void Harvest::writePcapFrame(const uint8_t* frame, uint16_t len) {
    if (!openPcap()) return;

    // Timestamps come from millis(): this board has no real-time clock, so the
    // capture opens at the epoch and the times inside it are relative. They are
    // correct relative to each other, which is what matters for reading a
    // handshake, and the README says so rather than letting anyone read 1970 as
    // a fault.
    const uint32_t ms = millis();
    uint8_t rec[d11::kPcapRecordHeaderLen];
    const size_t n = d11::writePcapRecordHeader(rec, sizeof(rec), ms / 1000,
                                                (ms % 1000) * 1000, len, len);
    pcap_.write(rec, n);
    pcap_.write(frame, len);
    pcapFrames_++;

    // Flushed often. The operator pulls the card out of a device that has no
    // shutdown, and an unflushed capture is a lost engagement.
    if ((pcapFrames_ % 4) == 0) pcap_.flush();
}

bool Harvest::saveHashes() {
    savedLines_ = 0;
    saveOk_     = false;
    if (!openPcap()) return false;   // also settles the file naming

    File f = SD.open(hashPath_, FILE_WRITE);
    if (!f) return false;

    // The whole table is rewritten each time rather than appended to, so saving
    // twice cannot produce a file with duplicate lines in it.
    char line[d11::kHashLineMax];
    for (uint8_t i = 0; i < table_.count(); i++) {
        const d11::Target& t = table_.at(i);
        if (d11::writePmkidLine(t, line, sizeof(line)) > 0) {
            f.println(line);
            savedLines_++;
        }
        if (d11::writeEapolLine(t, line, sizeof(line)) > 0) {
            f.println(line);
            savedLines_++;
        }
    }
    f.close();

    if (pcapOpen_) pcap_.flush();

    char detail[96];
    std::snprintf(detail, sizeof(detail), "harvest export lines=%u pcap=%u file=%s",
                  static_cast<unsigned>(savedLines_),
                  static_cast<unsigned>(pcapFrames_), hashPath_);
    app::recorder().note(evidence::RecordKind::Note, detail);

    saveOk_ = true;
    return true;
}

// ---- screens ----------------------------------------------------------------

void Harvest::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[24];
    std::snprintf(right, sizeof(right), "ch%u%s  %u", static_cast<unsigned>(channel_),
                  locked_ ? "*" : " ", static_cast<unsigned>(table_.count()));
    ui::chrome("Harvest", right);

    if (table_.count() == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString("Listening. Nothing yet.", 8, kBodyTop + 6);

        d.setTextColor(kFaint, kInk);
        ui::wrapText(8, kBodyTop + 22, bd::kScreenW - 16, 10, 4, kFaint,
                     "Handshakes happen when a client joins. Absence means a quiet "
                     "channel, not a safe network.");

        ui::textAt(8, kBodyTop + 68, kFaint, "%u frames   %u beacons",
                   static_cast<unsigned>(g_seen),
                   static_cast<unsigned>(beaconsSeen_));

        ui::footer("l lock   ` back");
        ui::endFrame();
        return;
    }

    if (selected_ >= static_cast<int>(table_.count()))
        selected_ = table_.count() - 1;
    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kRows) scroll_ = selected_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int idx = scroll_ + i;
        if (idx >= static_cast<int>(table_.count())) break;

        const d11::Target& t = table_.at(idx);
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        // An unnamed target still has to be identifiable, so it shows the last
        // three octets of its BSSID rather than a blank.
        char label[22];
        if (t.named()) {
            std::snprintf(label, sizeof(label), "%.18s", t.ssid);
        } else {
            std::snprintf(label, sizeof(label), "%02x%02x%02x", t.bssid[3], t.bssid[4],
                          t.bssid[5]);
        }
        d.setTextColor(t.named() ? kText : kMuted, bg);
        d.drawString(label, 8, mid);

        ui::textAt(124, mid, kFaint, "%u", static_cast<unsigned>(t.channel));
        signalBars(142, mid + 4, t.rssi, sel ? kShine : kBrass);

        d.setTextDatum(middle_right);
        d.setTextColor(qualityColour(t.quality()), bg);
        d.drawString(d11::qualityName(t.quality()), bd::kScreenW - 6, mid);
    }

    d.setTextDatum(top_left);
    ui::footer("enter  l lock  s save  ` back");
    ui::endFrame();
}

void Harvest::drawDetail() {
    if (table_.count() == 0) {
        view_ = View::List;
        return;
    }
    if (selected_ < 0 || selected_ >= static_cast<int>(table_.count()))
        selected_ = 0;

    ui::beginFrame();
    auto& d = ui::gfx();

    const d11::Target& t = table_.at(selected_);
    const d11::Quality q = t.quality();

    ui::chrome("Target", t.named() ? t.ssid : "(unnamed)");

    d.setFont(kFaceData);

    char ap[18];
    d11::formatMacColons(t.bssid, ap);
    ui::textAt(8, kBodyTop + 4, kMuted, "ap  %s", ap);
    char sta[18];
    d11::formatMacColons(t.sta, sta);
    ui::textAt(8, kBodyTop + 16, kMuted, "sta %s", sta);

    d.setTextDatum(middle_right);
    d.setTextColor(qualityColour(q), kInk);
    d.setFont(kFaceUi);
    d.drawString(d11::qualityName(q), bd::kScreenW - 6, kBodyTop + 10);
    d.setFont(kFaceData);

    // The message strip: which of the four we actually hold. Lit is held, dim
    // is missed -- the same "presence is proof, absence is not" grammar as the
    // coverage grid on Airspace.
    const bool have[4] = {t.haveM1, t.haveM2, t.haveM3, t.haveM4};
    const char* names[4] = {"M1", "M2", "M3", "M4"};
    for (int i = 0; i < 4; i++) {
        const int x = 8 + i * 26;
        d.setTextDatum(middle_left);
        d.setTextColor(have[i] ? kShine : kFaint, kInk);
        d.drawString(names[i], x, kBodyTop + 32);
    }

    d.setTextDatum(middle_left);
    if (t.havePmkid) {
        char pm[9];
        std::snprintf(pm, sizeof(pm), "%02x%02x%02x%02x", t.pmkid[0], t.pmkid[1],
                      t.pmkid[2], t.pmkid[3]);
        ui::textAt(116, kBodyTop + 32, kShine, "PMKID %s", pm);
    } else {
        ui::textAt(116, kBodyTop + 32, kFaint, "no pmkid");
    }

    uint8_t pair = 0;
    if (t.messagePair(pair)) {
        const bool checked = (pair & d11::kPairNotReplayChecked) == 0;
        ui::textAt(8, kBodyTop + 46, checked ? kGood : kMedium,
                   "pair %02x  %s", static_cast<unsigned>(pair),
                   checked ? "counters agree" : "counters differ");
    } else if (t.eapolOversize) {
        ui::textAt(8, kBodyTop + 46, kHigh, "M2 too long to store");
    } else {
        ui::textAt(8, kBodyTop + 46, kFaint, "no usable pair yet");
    }

    const int ruleY = bd::kScreenH - kFooterH - 34;
    d.drawFastHLine(6, ruleY, bd::kScreenW - 12, kRule);
    ui::wrapText(8, ruleY + 4, bd::kScreenW - 16, 10, 3, kMuted, d11::qualityDetail(q));

    d.setTextDatum(top_left);
    ui::footer("; . target   s save   ` back");
    ui::endFrame();
}

void Harvest::drawSaved() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Export");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (!saveOk_) {
        d.setTextColor(kCritical, kInk);
        d.drawString("Could not write to the card.", 8, kBodyTop + 8);
        d.setTextColor(kMuted, kInk);
        ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 3, kMuted,
                     "Check a microSD is seated. Nothing captured this session has "
                     "been lost; it is still in memory.");
    } else if (savedLines_ == 0) {
        d.setTextColor(kMuted, kInk);
        d.drawString("Nothing to export yet.", 8, kBodyTop + 8);
        ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 3, kFaint,
                     "A target needs a PMKID or a usable message pair before it can "
                     "become a hash line.");
    } else {
        d.setTextColor(kGood, kInk);
        ui::textAt(8, kBodyTop + 10, kGood, "%u hash line%s written",
                   static_cast<unsigned>(savedLines_), savedLines_ == 1 ? "" : "s");
        d.setTextColor(kMuted, kInk);
        d.drawString(hashPath_, 8, kBodyTop + 24);
        d.drawString(pcapPath_, 8, kBodyTop + 36);
        d.setTextColor(kFaint, kInk);
        ui::wrapText(8, kBodyTop + 54, bd::kScreenW - 16, 10, 3, kFaint,
                     "Crack elsewhere: hashcat -m 22000. This device does not "
                     "recover passphrases and does not guess at them.");
    }

    ui::footer("any key   back");
    ui::endFrame();
}

bool Harvest::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Saved) {
        view_ = View::List;
        return true;
    }

    if (ks.enter) {
        if (view_ == View::List && table_.count()) view_ = View::Detail;
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
                if (selected_ + 1 < static_cast<int>(table_.count())) selected_++;
                return true;

            case kKeyLock:
                // Locking is what actually catches handshakes. Hopping means
                // you are deaf to twelve channels out of thirteen; once a
                // target is chosen, staying on its channel is the whole tactic.
                locked_ = !locked_;
                if (locked_ && table_.count() &&
                    selected_ < static_cast<int>(table_.count())) {
                    const uint8_t ch = table_.at(selected_).channel;
                    if (ch >= 1 && ch <= kMaxChannel) {
                        channel_ = ch;
                        esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
                    }
                }
                return true;

            case kKeySave:
                saveHashes();
                view_ = View::Saved;
                return true;

            default:
                break;
        }
    }
    return true;
}

void Harvest::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        pump();

        if (!handleKeys()) {
            // Leave nothing running. Promiscuous mode off, radio off, capture
            // file closed -- an open file handle across a card removal is how
            // captures get truncated.
            esp_wifi_set_promiscuous(false);
            if (pcapOpen_) {
                pcap_.flush();
                pcap_.close();
                pcapOpen_ = false;
            }
            WiFi.mode(WIFI_OFF);
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::List:   drawList();   break;
                case View::Detail: drawDetail(); break;
                case View::Saved:  drawSaved();  break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
