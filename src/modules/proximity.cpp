#include "proximity.h"

#include <M5Cardputer.h>
#include <NimBLEDevice.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;

namespace {

constexpr uint32_t kRedrawMs = 220;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp     = ';';
constexpr char kKeyDown   = '.';
constexpr char kKeyBack   = '`';
constexpr char kKeyFilter = 'f';
constexpr char kKeyActive = 'a';

// ---- the ring between the NimBLE host task and the UI loop ------------------
//
// Same discipline as Harvest: the callback runs in somebody else's task, so it
// copies and returns. An advertisement is at most 31 bytes, and a scan response
// adds another 31.

constexpr uint8_t  kSlots      = 12;
constexpr uint16_t kPayloadMax = 62;

struct Slot {
    uint8_t  addr[6] = {0};
    bool     randomAddress = false;
    int8_t   rssi = 0;
    uint16_t len  = 0;
    uint8_t  data[kPayloadMax] = {0};
};

Slot             g_ring[kSlots];
volatile uint8_t g_head = 0;
volatile uint8_t g_tail = 0;
volatile uint32_t g_adverts  = 0;
volatile uint32_t g_overruns = 0;

class ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* d) override {
        if (d == nullptr) return;
        g_adverts++;

        const uint8_t next = static_cast<uint8_t>((g_head + 1) % kSlots);
        if (next == g_tail) {
            g_overruns++;
            return;
        }

        Slot& s = g_ring[g_head];

        // NimBLE stores an address least significant byte first: its
        // constructor reverse-copies from the ESP representation. Reversing it
        // back here is not cosmetic -- the address KIND lives in the top two
        // bits of the most significant byte, and reading the wrong end reports
        // every rotating address as a fixed one.
        const uint8_t* native = d->getAddress().getNative();
        for (int i = 0; i < 6; i++) s.addr[i] = native[5 - i];

        s.randomAddress = (d->getAddressType() != BLE_ADDR_PUBLIC);
        s.rssi = static_cast<int8_t>(d->getRSSI());

        size_t n = d->getPayloadLength();
        if (n > kPayloadMax) n = kPayloadMax;
        if (n && d->getPayload()) std::memcpy(s.data, d->getPayload(), n);
        s.len = static_cast<uint16_t>(n);

        g_head = next;
    }
};

ScanCallbacks g_callbacks;
NimBLEScan*   g_scan = nullptr;

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

uint16_t kindColour(ble::Kind k) {
    if (ble::isTracker(k)) return kHigh;
    switch (k) {
        case ble::Kind::IBeacon:
        case ble::Kind::Eddystone:  return kInfo;
        case ble::Kind::Continuity:
        case ble::Kind::FastPair:   return kMuted;
        default:                    return kFaint;
    }
}

}  // namespace

bool Proximity::begin() {
    count_ = 0;
    for (uint8_t i = 0; i < kMaxDevices; i++) devices_[i] = Device{};
    g_head = g_tail = 0;
    g_adverts = g_overruns = 0;
    trackersSeen_ = 0;
    enteredMs_ = millis();

    NimBLEDevice::init("");
    g_scan = NimBLEDevice::getScan();
    if (g_scan == nullptr) return false;

    g_scan->setAdvertisedDeviceCallbacks(&g_callbacks, /*wantDuplicates=*/true);
    // Passive. An active scan transmits a scan request to every device it
    // hears, and that is the operator's call to make, not the default.
    g_scan->setActiveScan(activeScan_);
    g_scan->setInterval(100);
    g_scan->setWindow(99);
    // Results are handled in the callback, so NimBLE must not also keep its own
    // growing list of them. On a board with no PSRAM that list is the leak.
    g_scan->setMaxResults(0);
    g_scan->start(0, nullptr, false);
    return true;
}

int Proximity::find(const uint8_t addr[ble::kAddrLen]) const {
    for (uint8_t i = 0; i < count_; i++)
        if (std::memcmp(devices_[i].addr, addr, ble::kAddrLen) == 0)
            return static_cast<int>(i);
    return -1;
}

void Proximity::ingest(const uint8_t addr[ble::kAddrLen], bool randomAddress,
                       int8_t rssi, const uint8_t* payload, size_t payloadLen) {
    ble::Advert a;
    ble::parseAdvert(payload, payloadLen, a);

    int idx = find(addr);
    if (idx < 0) {
        if (count_ >= kMaxDevices) {
            // A device already in the table that has not been heard for a
            // while is a fair trade for one that is here now. Evicting the
            // stalest keeps the list describing the room the operator is
            // standing in.
            int oldest = 0;
            for (uint8_t i = 1; i < count_; i++)
                if (devices_[i].lastSeenMs < devices_[oldest].lastSeenMs) oldest = i;
            devices_[oldest] = Device{};
            idx = oldest;
        } else {
            idx = count_++;
            devices_[idx] = Device{};
        }
        std::memcpy(devices_[idx].addr, addr, ble::kAddrLen);
        devices_[idx].randomAddress = randomAddress;
        devices_[idx].addrKind = ble::addressKind(addr, randomAddress);
        devices_[idx].firstSeenMs = millis();
    }

    Device& d = devices_[idx];
    d.sightings++;
    d.lastSeenMs = millis();
    d.rssi = rssi;
    if (rssi > d.bestRssi) d.bestRssi = rssi;

    // A scan response arrives as a separate packet from the advertisement, so
    // fields are merged in rather than overwritten -- otherwise the name from
    // one packet is wiped by the next packet that does not carry it.
    if (a.hasName && !d.hasName) {
        std::snprintf(d.name, ble::kNameBuf, "%s", a.name);
        d.hasName = true;
    }
    if (a.hasCompany) {
        d.companyId  = a.companyId;
        d.hasCompany = true;
    }
    if (a.hasTxPower) {
        d.txPower    = a.txPower;
        d.hasTxPower = true;
    }
    if (a.serviceCount) {
        d.service    = a.services[0];
        d.hasService = true;
    }

    const ble::Kind k = ble::classify(a);
    if (k != ble::Kind::Generic) d.kind = k;

    if (ble::isTracker(d.kind) && !d.logged) {
        d.logged = true;
        trackersSeen_++;

        char mac[18];
        std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", d.addr[0],
                      d.addr[1], d.addr[2], d.addr[3], d.addr[4], d.addr[5]);
        char detail[96];
        std::snprintf(detail, sizeof(detail), "ble tracker=%s addr=%s kind=%s rssi=%d",
                      ble::kindName(d.kind), mac,
                      ble::addressKindName(d.addrKind), static_cast<int>(rssi));
        app::recorder().noteDevice(detail);
    }
}

void Proximity::drain() {
    for (int budget = 0; budget < 8; budget++) {
        if (g_tail == g_head) return;
        const Slot& s = g_ring[g_tail];
        ingest(s.addr, s.randomAddress, s.rssi, s.data, s.len);
        g_tail = static_cast<uint8_t>((g_tail + 1) % kSlots);
    }
}

// ---- filtering ---------------------------------------------------------------

int Proximity::visibleCount() const {
    if (!trackersOnly_) return count_;
    int n = 0;
    for (uint8_t i = 0; i < count_; i++)
        if (ble::isTracker(devices_[i].kind)) n++;
    return n;
}

int Proximity::visibleAt(int i) const {
    if (!trackersOnly_) return i;
    int n = 0;
    for (uint8_t k = 0; k < count_; k++) {
        if (!ble::isTracker(devices_[k].kind)) continue;
        if (n == i) return static_cast<int>(k);
        n++;
    }
    return -1;
}

// ---- screens -----------------------------------------------------------------

void Proximity::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const int visible = visibleCount();

    char right[24];
    std::snprintf(right, sizeof(right), "%d%s%s", visible,
                  trackersOnly_ ? " tag" : " dev", activeScan_ ? " A" : "");
    ui::chrome("Proximity", right);

    if (visible == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString(trackersOnly_ ? "No trackers in range." : "Listening...", 8,
                     kBodyTop + 6);

        ui::wrapText(8, kBodyTop + 22, bd::kScreenW - 16, 10, 4, kFaint,
                     trackersOnly_
                         ? "Nothing here is advertising as an item finder. That is "
                           "one room, at one moment -- not a clean bill of health."
                         : "Passive: nothing is transmitted. Most devices advertise "
                           "a few times a second, so this fills quickly.");

        ui::textAt(8, bd::kScreenH - kFooterH - 10, kFaint, "%u adverts   %u devices",
                   static_cast<unsigned>(g_adverts),
                   static_cast<unsigned>(count_));
        ui::footer("f filter   a active   ` back");
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

        const Device& dev = devices_[idx];
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (vis == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        // An unnamed device shows the last three octets of its address. Most
        // devices have no name, and a list of blanks is unusable.
        char label[20];
        if (dev.hasName) {
            std::snprintf(label, sizeof(label), "%.16s", dev.name);
        } else {
            std::snprintf(label, sizeof(label), "%02x%02x%02x", dev.addr[3],
                          dev.addr[4], dev.addr[5]);
        }
        d.setTextColor(dev.hasName ? kText : kMuted, bg);
        d.drawString(label, 8, mid);

        d.setTextColor(kindColour(dev.kind), bg);
        d.drawString(ble::kindName(dev.kind), 110, mid);

        signalBars(178, mid + 4, dev.rssi, sel ? kShine : kBrass);

        d.setTextDatum(middle_right);
        d.setTextColor(kFaint, bg);
        d.drawString(ble::proximityName(
                         ble::proximityFor(dev.rssi, dev.hasTxPower, dev.txPower)),
                     bd::kScreenW - 6, mid);
    }

    d.setTextDatum(top_left);
    ui::footer("enter  f filter  a active  ` back");
    ui::endFrame();
}

void Proximity::drawDetail() {
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
    const Device& dev = devices_[idx];

    ui::chrome("Device", ble::kindName(dev.kind));

    d.setFont(kFaceData);
    ui::textAt(8, kBodyTop + 5, kText, "%s",
               dev.hasName ? dev.name : "(no name advertised)");

    char mac[18];
    std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", dev.addr[0],
                  dev.addr[1], dev.addr[2], dev.addr[3], dev.addr[4], dev.addr[5]);
    ui::textAt(8, kBodyTop + 17, kMuted, "%s", mac);

    // The single most useful privacy fact about any device here: whether this
    // address will still be this address in fifteen minutes.
    const bool stable = ble::addressIsStable(dev.addrKind);
    ui::textAt(8, kBodyTop + 29, stable ? kHigh : kGood, "%s address",
               ble::addressKindName(dev.addrKind));

    if (dev.hasCompany) {
        const char* vendor = ble::companyName(dev.companyId);
        if (vendor) ui::textRight(bd::kScreenW - 6, kBodyTop + 29, kFaint, "%s", vendor);
        else        ui::textRight(bd::kScreenW - 6, kBodyTop + 29, kFaint, "0x%04x",
                                  static_cast<unsigned>(dev.companyId));
    }

    ui::textRight(bd::kScreenW - 6, kBodyTop + 5, kFaint, "%d dBm",
                  static_cast<int>(dev.rssi));
    ui::textRight(bd::kScreenW - 6, kBodyTop + 17, kFaint, "%u seen",
                  static_cast<unsigned>(dev.sightings));

    const int ruleY = bd::kScreenH - kFooterH - 40;
    d.drawFastHLine(6, ruleY, bd::kScreenW - 12, kRule);
    ui::wrapText(8, ruleY + 4, bd::kScreenW - 16, 10, 4, kMuted,
                 ble::kindDetail(dev.kind));

    d.setTextDatum(top_left);
    ui::footer("; . device   ` back");
    ui::endFrame();
}

bool Proximity::handleKeys() {
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

            case kKeyFilter:
                trackersOnly_ = !trackersOnly_;
                selected_ = 0;
                scroll_   = 0;
                return true;

            case kKeyActive:
                // Restarted rather than toggled in place: NimBLE reads the scan
                // type when a scan starts, so flipping the flag on a running
                // scan changes the label and nothing else.
                activeScan_ = !activeScan_;
                if (g_scan) {
                    g_scan->stop();
                    g_scan->setActiveScan(activeScan_);
                    g_scan->start(0, nullptr, false);
                }
                return true;

            default:
                break;
        }
    }
    return true;
}

void Proximity::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        drain();

        if (!handleKeys()) {
            if (g_scan) {
                g_scan->stop();
                g_scan->setAdvertisedDeviceCallbacks(nullptr);
            }
            // Released rather than left running. The BLE stack holds tens of
            // kilobytes, and the next surface may want the frame buffer.
            NimBLEDevice::deinit(true);
            g_scan = nullptr;
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            if (view_ == View::List) drawList();
            else                     drawDetail();
        }
        delay(5);
    }
}

}  // namespace orthrus::modules
