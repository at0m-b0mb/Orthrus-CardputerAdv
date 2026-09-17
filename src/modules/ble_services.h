// Services: what a Bluetooth device actually exposes.
//
// Devices finds what is advertising. This is the next question on an
// engagement: connect to one and read its GATT database -- the services it
// offers, the characteristics inside them, and which of those anyone in range
// can read or write without pairing at all.
//
// That last part is the finding. A lock, a sensor or a medical device with a
// world-writable characteristic is a real defect, and it is invisible from a
// scan.
//
// THREE THINGS THIS IS BUILT AROUND, ALL LEARNED FROM THE LIBRARY'S SOURCE
//
// 1. CONNECT BY ADDRESS, NEVER BY POINTER. The Devices surface runs its scan
//    with setMaxResults(0), which makes NimBLE delete each advertised device
//    the moment the callback returns. Holding that pointer and connecting to it
//    later is a use-after-free. The address is copied out as six bytes and a
//    fresh NimBLEAddress is built from them.
//
// 2. NOTHING HERE RUNS IN THE SCAN CALLBACK. connect(), discovery and
//    readValue() all block the calling task, and the scan callback IS the
//    NimBLE host task -- blocking it deadlocks the stack against itself.
//
// 3. READING IS OPT-IN, PER CHARACTERISTIC. NimBLE's readValue() silently
//    starts a pairing or bonding exchange if the peer answers with an
//    authentication error, and that wait has NO timeout at all. It would also
//    put a pairing prompt on somebody's phone without the operator asking for
//    one. So enumeration never reads: it lists what is there, and a value is
//    only fetched when the operator presses the key, having been told what that
//    can trigger.

#pragma once

#include <cstdint>

namespace orthrus::modules {

class BleServices {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { Scanning, Devices, Connecting, Gatt, Value, Failed };

    static constexpr uint8_t kMaxDevices = 16;
    static constexpr uint8_t kMaxEntries = 40;   // services and characteristics, flat
    static constexpr uint8_t kUuidLen    = 37;   // a 128-bit UUID is 36 chars
    static constexpr uint8_t kNameLen    = 21;
    static constexpr uint8_t kValueBytes = 24;

    struct Device {
        uint8_t addr[6] = {0};
        bool    randomAddress = false;
        char    name[kNameLen] = {0};
        int8_t  rssi = 0;
    };

    // Services and their characteristics in one flat list, because a 135 px
    // panel shows a flat list and a tree costs more than it explains.
    struct Entry {
        bool    isService = false;
        char    uuid[kUuidLen] = {0};
        uint16_t handle = 0;
        bool    canRead = false, canWrite = false, canNotify = false;
        bool    writeNoRsp = false, canIndicate = false;
    };

    void startScan();
    void stopScan();
    void keepScanning();
    void drainScan();
    bool connectAndWalk();
    void readSelected();

    void drawScanning();
    void drawDevices();
    void drawConnecting();
    void drawGatt();
    void drawValue();
    void drawFailed();
    bool handleKeys();

    Device  devices_[kMaxDevices];
    uint8_t deviceCount_ = 0;
    int     deviceSel_   = 0;
    int     deviceScroll_ = 0;

    Entry   entries_[kMaxEntries];
    uint8_t entryCount_ = 0;
    int     entrySel_   = 0;
    int     entryScroll_ = 0;
    uint8_t serviceCount_ = 0;
    bool    truncated_    = false;

    uint8_t  value_[kValueBytes] = {0};
    uint8_t  valueLen_  = 0;
    bool     valueOk_   = false;
    char     valueNote_[64] = {0};

    char     failure_[72] = {0};
    uint32_t enteredMs_   = 0;

    View     view_       = View::Scanning;
    uint32_t lastScanCheckMs_ = 0;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
