#include "ble_services.h"

#include <M5Cardputer.h>
#include <NimBLEDevice.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "ble/advert.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;

// A tiny shim so the property letters can be built without exposing the nested
// Entry type to the helpers below.
struct BleServicesEntryProps {
    bool canRead, canWrite, writeNoRsp, canNotify, canIndicate;
};

namespace {

constexpr uint32_t kRedrawMs = 200;
constexpr uint32_t kScanMs   = 6000;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyBack  = '`';
constexpr char kKeyRead  = 'r';
constexpr char kKeyAgain = 's';

// Seconds, and it is a uint8_t -- passing milliseconds here silently truncates
// to something meaningless. The library's own default is thirty seconds, which
// would freeze the UI for half a minute on a peer that has walked away.
constexpr uint8_t kConnectTimeoutS = 8;

// ---- the scan side ----------------------------------------------------------
//
// A small scan of its own rather than borrowing the Devices surface's table:
// this screen needs an address it can still use a minute later, and the two
// modules having independent lifetimes is worth more than the sharing.

struct Seen {
    uint8_t addr[6];
    bool    randomAddress;
    char    name[21];
    int8_t  rssi;
};

constexpr uint8_t kRingSlots = 12;
Seen              g_ring[kRingSlots];
volatile uint8_t  g_head = 0;
volatile uint8_t  g_tail = 0;

class ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* d) override {
        if (d == nullptr) return;
        const uint8_t next = static_cast<uint8_t>((g_head + 1) % kRingSlots);
        if (next == g_tail) return;

        Seen& s = g_ring[g_head];

        // NimBLE stores an address least significant byte first. Reversing it
        // here is what makes the displayed address match the one on the peer,
        // and it is the form NimBLEAddress wants handed back to it later.
        const uint8_t* native = d->getAddress().getNative();
        for (int i = 0; i < 6; i++) s.addr[i] = native[5 - i];

        s.randomAddress = (d->getAddressType() != BLE_ADDR_PUBLIC);
        s.rssi          = static_cast<int8_t>(d->getRSSI());
        s.name[0]       = '\0';

        // The name comes out of the advertisement we parse ourselves, not from
        // getName(), so one code path decides what a name is.
        ble::Advert a;
        if (d->getPayload() && d->getPayloadLength()) {
            ble::parseAdvert(d->getPayload(), d->getPayloadLength(), a);
            // Clipped on purpose, and said so: a BLE name is up to 24 bytes and
            // the row it goes in is narrower than that. The precision keeps it
            // a deliberate display width rather than an accidental overflow.
            if (a.hasName) std::snprintf(s.name, sizeof(s.name), "%.20s", a.name);
        }

        g_head = next;
    }
};

ScanCallbacks g_callbacks;
NimBLEScan*   g_scan = nullptr;

void propLetters(const BleServicesEntryProps& p, char* out, size_t cap) {
    size_t n = 0;
    if (p.canRead     && n + 1 < cap) out[n++] = 'R';
    if (p.canWrite    && n + 1 < cap) out[n++] = 'W';
    if (p.writeNoRsp  && n + 1 < cap) out[n++] = 'w';
    if (p.canNotify   && n + 1 < cap) out[n++] = 'N';
    if (p.canIndicate && n + 1 < cap) out[n++] = 'I';
    out[n] = '\0';
}

// A 128-bit UUID is 36 characters and will not fit a 240 px line in any face
// worth reading. Standard 16-bit UUIDs print short already; long ones are
// shown head and tail so two different ones never look the same.
void shortUuid(const char* uuid, char* out, size_t cap) {
    const size_t n = std::strlen(uuid);
    if (n <= 20) {
        std::snprintf(out, cap, "%s", uuid);
        return;
    }
    std::snprintf(out, cap, "%.8s..%.6s", uuid, uuid + n - 6);
}

}  // namespace

bool BleServices::begin() {
    deviceCount_ = 0;
    entryCount_  = 0;
    deviceSel_   = 0;
    entrySel_    = 0;
    view_        = View::Scanning;
    enteredMs_   = millis();

    NimBLEDevice::init("");
    g_scan = NimBLEDevice::getScan();
    if (g_scan == nullptr) return false;

    startScan();
    return true;
}

void BleServices::startScan() {
    g_head = g_tail = 0;
    deviceCount_ = 0;
    enteredMs_   = millis();
    view_        = View::Scanning;

    g_scan->setAdvertisedDeviceCallbacks(&g_callbacks, /*wantDuplicates=*/false);
    // ACTIVE here, unlike the Devices surface. This screen exists to connect to
    // something, so the operator has already decided to talk to it -- and a
    // name makes choosing the right one possible.
    g_scan->setActiveScan(true);
    g_scan->setInterval(100);
    g_scan->setWindow(99);
    g_scan->setMaxResults(0);
    g_scan->start(0, nullptr, false);
}

void BleServices::stopScan() {
    if (g_scan) {
        g_scan->stop();
        g_scan->setAdvertisedDeviceCallbacks(nullptr);
    }
}

void BleServices::drainScan() {
    while (g_tail != g_head) {
        const Seen& s = g_ring[g_tail];

        int found = -1;
        for (uint8_t i = 0; i < deviceCount_; i++) {
            if (std::memcmp(devices_[i].addr, s.addr, 6) == 0) { found = i; break; }
        }
        if (found < 0 && deviceCount_ < kMaxDevices) {
            found = deviceCount_++;
            devices_[found] = Device{};
            std::memcpy(devices_[found].addr, s.addr, 6);
            devices_[found].randomAddress = s.randomAddress;
        }
        if (found >= 0) {
            devices_[found].rssi = s.rssi;
            if (s.name[0] && devices_[found].name[0] == '\0')
                std::snprintf(devices_[found].name, kNameLen, "%s", s.name);
        }

        g_tail = static_cast<uint8_t>((g_tail + 1) % kRingSlots);
    }
}

bool BleServices::connectAndWalk() {
    entryCount_   = 0;
    serviceCount_ = 0;
    truncated_    = false;
    failure_[0]   = '\0';

    if (deviceSel_ < 0 || deviceSel_ >= static_cast<int>(deviceCount_)) return false;
    const Device& dev = devices_[deviceSel_];

    // The scan has to stop before a connection, and stopping it here rather
    // than letting connect() discover the conflict keeps the failure visible.
    stopScan();
    delay(50);

    // Rebuilt from our own six bytes. The pointer NimBLE handed the callback
    // was freed the moment that callback returned -- setMaxResults(0) makes the
    // scan delete each device immediately -- so connecting to it would be a
    // use-after-free.
    uint8_t raw[6];
    std::memcpy(raw, dev.addr, 6);
    NimBLEAddress target(raw, dev.randomAddress ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC);

    NimBLEClient* client = NimBLEDevice::createClient();
    if (client == nullptr) {
        std::snprintf(failure_, sizeof(failure_), "Could not create a client.");
        return false;
    }

    client->setConnectTimeout(kConnectTimeoutS);
    // A four second supervision timeout is not a nicety. Discovery and reads
    // block with NO timeout of their own and only unblock when the link drops,
    // so this is the only thing that rescues the UI from a peer that stops
    // answering mid-walk.
    client->setConnectionParams(24, 40, 0, 400);

    if (!client->connect(target, /*deleteAttributes=*/true)) {
        std::snprintf(failure_, sizeof(failure_),
                      "Connect refused or timed out (err %d).",
                      client->getLastError());
        NimBLEDevice::deleteClient(client);
        return false;
    }

    std::vector<NimBLERemoteService*>* services = client->getServices(true);
    if (services != nullptr) {
        for (NimBLERemoteService* svc : *services) {
            if (entryCount_ >= kMaxEntries) { truncated_ = true; break; }

            // Bound to a named string: getUUID() returns by value and
            // toString() returns by value, so taking c_str() off the temporary
            // in the same expression leaves a dangling pointer.
            const std::string su = svc->getUUID().toString();
            Entry& e = entries_[entryCount_++];
            e = Entry{};
            e.isService = true;
            std::snprintf(e.uuid, kUuidLen, "%s", su.c_str());
            serviceCount_++;

            std::vector<NimBLERemoteCharacteristic*>* chars =
                svc->getCharacteristics(true);
            if (chars == nullptr) continue;

            for (NimBLERemoteCharacteristic* ch : *chars) {
                if (entryCount_ >= kMaxEntries) { truncated_ = true; break; }
                const std::string cu = ch->getUUID().toString();
                Entry& c = entries_[entryCount_++];
                c = Entry{};
                c.isService  = false;
                std::snprintf(c.uuid, kUuidLen, "%s", cu.c_str());
                c.handle     = ch->getHandle();
                // 1.x has no getProperties(); these predicates are the API.
                c.canRead     = ch->canRead();
                c.canWrite    = ch->canWrite();
                c.writeNoRsp  = ch->canWriteNoResponse();
                c.canNotify   = ch->canNotify();
                c.canIndicate = ch->canIndicate();

                if (!client->isConnected()) break;
            }
            if (!client->isConnected()) break;
        }
    }

    // Nothing here is read. Enumeration only -- see the header for why.
    client->disconnect();
    uint32_t guard = 0;
    while (client->isConnected() && guard++ < 2000) delay(1);
    NimBLEDevice::deleteClient(client);

    char mac[18];
    std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", dev.addr[0],
                  dev.addr[1], dev.addr[2], dev.addr[3], dev.addr[4], dev.addr[5]);
    char detail[96];
    std::snprintf(detail, sizeof(detail), "ble gatt addr=%s services=%u attrs=%u",
                  mac, static_cast<unsigned>(serviceCount_),
                  static_cast<unsigned>(entryCount_));
    app::recorder().noteDevice(detail);

    if (entryCount_ == 0) {
        std::snprintf(failure_, sizeof(failure_),
                      "Connected, but it exposed nothing readable.");
        return false;
    }
    return true;
}

void BleServices::readSelected() {
    valueLen_ = 0;
    valueOk_  = false;
    valueNote_[0] = '\0';

    if (entrySel_ < 0 || entrySel_ >= static_cast<int>(entryCount_)) return;
    const Entry& e = entries_[entrySel_];
    if (e.isService || !e.canRead) {
        std::snprintf(valueNote_, sizeof(valueNote_),
                      "Not a readable characteristic.");
        view_ = View::Value;
        return;
    }

    const Device& dev = devices_[deviceSel_];
    uint8_t raw[6];
    std::memcpy(raw, dev.addr, 6);
    NimBLEAddress target(raw, dev.randomAddress ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC);

    NimBLEClient* client = NimBLEDevice::createClient();
    if (client == nullptr) return;
    client->setConnectTimeout(kConnectTimeoutS);
    client->setConnectionParams(24, 40, 0, 400);

    if (!client->connect(target, false)) {
        std::snprintf(valueNote_, sizeof(valueNote_), "Could not reconnect.");
        NimBLEDevice::deleteClient(client);
        view_ = View::Value;
        return;
    }

    // Walk back to the characteristic by handle. Re-resolving rather than
    // holding a pointer across the disconnect, because those objects belonged
    // to the client that has since been deleted.
    NimBLERemoteCharacteristic* target_ch = nullptr;
    std::vector<NimBLERemoteService*>* services = client->getServices(true);
    if (services != nullptr) {
        for (NimBLERemoteService* svc : *services) {
            std::vector<NimBLERemoteCharacteristic*>* chars =
                svc->getCharacteristics(true);
            if (chars == nullptr) continue;
            for (NimBLERemoteCharacteristic* ch : *chars) {
                if (ch->getHandle() == e.handle) { target_ch = ch; break; }
            }
            if (target_ch) break;
        }
    }

    if (target_ch == nullptr) {
        std::snprintf(valueNote_, sizeof(valueNote_),
                      "That attribute is no longer there.");
    } else {
        NimBLEAttValue v = target_ch->readValue();
        uint16_t n = v.length();
        if (n > kValueBytes) n = kValueBytes;
        if (n) std::memcpy(value_, v.data(), n);
        valueLen_ = static_cast<uint8_t>(n);
        valueOk_  = true;
        std::snprintf(valueNote_, sizeof(valueNote_), "%u bytes returned",
                      static_cast<unsigned>(v.length()));
    }

    client->disconnect();
    uint32_t guard = 0;
    while (client->isConnected() && guard++ < 2000) delay(1);
    NimBLEDevice::deleteClient(client);
    view_ = View::Value;
}

// ---- screens -----------------------------------------------------------------

void BleServices::drawScanning() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u", static_cast<unsigned>(deviceCount_));
    ui::chrome("Services", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Scanning for something to ask.", 8, kBodyTop + 8);

    ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 4, kFaint,
                 "Active scan: this screen exists to connect, so it asks each "
                 "device for its name. That transmits.");

    ui::footer("` back");
    ui::endFrame();
}

void BleServices::drawDevices() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u", static_cast<unsigned>(deviceCount_));
    ui::chrome("Services", right);

    if (deviceSel_ >= static_cast<int>(deviceCount_)) deviceSel_ = deviceCount_ - 1;
    if (deviceSel_ < 0) deviceSel_ = 0;
    if (deviceSel_ < deviceScroll_) deviceScroll_ = deviceSel_;
    if (deviceSel_ >= deviceScroll_ + kRows) deviceScroll_ = deviceSel_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int idx = deviceScroll_ + i;
        if (idx >= static_cast<int>(deviceCount_)) break;

        const Device& dev = devices_[idx];
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == deviceSel_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        char label[24];
        if (dev.name[0]) std::snprintf(label, sizeof(label), "%.18s", dev.name);
        else             std::snprintf(label, sizeof(label), "%02x%02x%02x",
                                       dev.addr[3], dev.addr[4], dev.addr[5]);
        d.setTextColor(dev.name[0] ? kText : kMuted, bg);
        d.drawString(label, 8, mid);

        d.setTextColor(dev.randomAddress ? kFaint : kBrass, bg);
        d.drawString(dev.randomAddress ? "random" : "public", 140, mid);

        d.setTextDatum(middle_right);
        d.setTextColor(kFaint, bg);
        char r[10];
        std::snprintf(r, sizeof(r), "%d", static_cast<int>(dev.rssi));
        d.drawString(r, bd::kScreenW - 6, mid);
    }

    d.setTextDatum(top_left);
    ui::footer("enter connect   s rescan   ` back");
    ui::endFrame();
}

void BleServices::drawConnecting() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Connecting");

    const Device& dev = devices_[deviceSel_];

    d.setFont(kFaceUi);
    d.setTextDatum(middle_left);
    d.setTextColor(kText, kInk);
    d.drawString(dev.name[0] ? dev.name : "(unnamed)", 8, kBodyTop + 14);

    d.setFont(kFaceData);
    ui::wrapText(8, kBodyTop + 32, bd::kScreenW - 16, 11, 4, kMuted,
                 "Connecting and reading the attribute table. The screen will "
                 "not react until this finishes -- the library's calls block, "
                 "and pretending otherwise would be a lie.");

    ui::footer("");
    ui::endFrame();
}

void BleServices::drawGatt() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[20];
    std::snprintf(right, sizeof(right), "%u svc%s", static_cast<unsigned>(serviceCount_),
                  truncated_ ? "+" : "");
    ui::chrome("GATT", right);

    if (entrySel_ >= static_cast<int>(entryCount_)) entrySel_ = entryCount_ - 1;
    if (entrySel_ < 0) entrySel_ = 0;
    if (entrySel_ < entryScroll_) entryScroll_ = entrySel_;
    if (entrySel_ >= entryScroll_ + kRows) entryScroll_ = entrySel_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int idx = entryScroll_ + i;
        if (idx >= static_cast<int>(entryCount_)) break;

        const Entry& e = entries_[idx];
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == entrySel_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        char shown[24];
        shortUuid(e.uuid, shown, sizeof(shown));

        if (e.isService) {
            d.setTextColor(kBrass, bg);
            d.drawString(shown, 8, mid);
        } else {
            d.setTextColor(kText, bg);
            d.drawString(shown, 16, mid);

            const BleServicesEntryProps p{e.canRead, e.canWrite, e.writeNoRsp,
                                          e.canNotify, e.canIndicate};
            char letters[8];
            propLetters(p, letters, sizeof(letters));
            d.setTextDatum(middle_right);
            // A writable characteristic on a device nobody paired with is the
            // finding this screen exists for, so it is the one that is coloured.
            d.setTextColor((e.canWrite || e.writeNoRsp) ? kHigh : kFaint, bg);
            d.drawString(letters, bd::kScreenW - 6, mid);
        }
    }

    d.setTextDatum(top_left);
    ui::footer("r read   ; . move   ` back");
    ui::endFrame();
}

void BleServices::drawValue() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Value");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (!valueOk_) {
        d.setTextColor(kMedium, kInk);
        ui::wrapText(8, kBodyTop + 8, bd::kScreenW - 16, 11, 3, kMedium, valueNote_);
        ui::footer("any key   back");
        ui::endFrame();
        return;
    }

    d.setTextColor(kFaint, kInk);
    d.drawString(valueNote_, 8, kBodyTop + 4);

    int y = kBodyTop + 18;
    for (uint8_t off = 0; off < valueLen_ && y < bd::kScreenH - kFooterH - 20;
         off += 8) {
        char row[40];
        int w = 0;
        for (uint8_t i = 0; i < 8 && off + i < valueLen_; i++)
            w += std::snprintf(row + w, sizeof(row) - w, "%02x ",
                               static_cast<unsigned>(value_[off + i]));
        d.setTextColor(kText, kInk);
        d.drawString(row, 8, y);
        y += 11;
    }

    // Printable bytes, because half of what sits in a readable characteristic
    // is a model number or a firmware string.
    char ascii[kValueBytes + 1];
    uint8_t n = 0;
    for (uint8_t i = 0; i < valueLen_; i++) {
        const unsigned char ch = value_[i];
        ascii[n++] = (ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '.';
    }
    ascii[n] = '\0';
    d.setTextColor(kShine, kInk);
    d.drawString(ascii, 8, bd::kScreenH - kFooterH - 14);

    ui::footer("any key   back");
    ui::endFrame();
}

void BleServices::drawFailed() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Services", "failed");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    ui::wrapText(8, kBodyTop + 8, bd::kScreenW - 16, 11, 3, kCritical, failure_);

    d.setTextColor(kMuted, kInk);
    ui::wrapText(8, kBodyTop + 48, bd::kScreenW - 16, 10, 4, kMuted,
                 "Most devices refuse a connection from a stranger, and that is "
                 "them behaving correctly. It is not a fault in the scan.");

    ui::footer("any key   back");
    ui::endFrame();
}

bool BleServices::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Value)  { view_ = View::Gatt;    return true; }
    if (view_ == View::Failed) { view_ = View::Devices; return true; }
    if (view_ == View::Connecting) return true;   // blocked anyway

    if (ks.enter) {
        if ((view_ == View::Devices || view_ == View::Scanning) && deviceCount_) {
            view_ = View::Connecting;
            drawConnecting();          // drawn BEFORE the blocking call
            view_ = connectAndWalk() ? View::Gatt : View::Failed;
            entrySel_ = entryScroll_ = 0;
        }
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Gatt) { view_ = View::Devices; return true; }
                return false;

            case kKeyUp:
                if (view_ == View::Gatt) { if (entrySel_ > 0) entrySel_--; }
                else if (deviceSel_ > 0) deviceSel_--;
                return true;

            case kKeyDown:
                if (view_ == View::Gatt) {
                    if (entrySel_ + 1 < static_cast<int>(entryCount_)) entrySel_++;
                } else if (deviceSel_ + 1 < static_cast<int>(deviceCount_)) {
                    deviceSel_++;
                }
                return true;

            case kKeyRead:
                if (view_ == View::Gatt) readSelected();
                return true;

            case kKeyAgain:
                if (view_ != View::Gatt) startScan();
                return true;

            default:
                break;
        }
    }
    return true;
}

void BleServices::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        if (view_ == View::Scanning || view_ == View::Devices) drainScan();

        if (view_ == View::Scanning && deviceCount_ &&
            millis() - enteredMs_ > kScanMs)
            view_ = View::Devices;

        if (!handleKeys()) {
            stopScan();
            NimBLEDevice::deinit(true);
            g_scan = nullptr;
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Scanning:   drawScanning();   break;
                case View::Devices:    drawDevices();    break;
                case View::Connecting: drawConnecting(); break;
                case View::Gatt:       drawGatt();       break;
                case View::Value:      drawValue();      break;
                case View::Failed:     drawFailed();     break;
            }
        }
        delay(5);
    }
}

}  // namespace orthrus::modules
