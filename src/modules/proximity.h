// Proximity: what is advertising itself over Bluetooth Low Energy.
//
// Every phone, earbud, watch and luggage tag in a room shouts a small packet
// several times a second, unencrypted, to nobody in particular. This surface
// listens to that and sorts it into things that matter.
//
// PASSIVE BY DEFAULT, AND THE DIFFERENCE IS REAL
//
// A passive scan only listens. An ACTIVE scan transmits a scan request to each
// device it hears, asking for the rest of its data -- which is how you get
// names out of devices that do not advertise one, and which also means the
// device is no longer silent. That is a decision the operator should make
// knowingly, so it is a key press with the consequence written next to it,
// never the default.
//
// THE CLAIM THIS SURFACE WILL NOT MAKE
//
// Seeing a tracker is not seeing a stalker. A Find My advert means an Apple
// device is in offline-finding mode within about ten metres of you, right now.
// Whether it is FOLLOWING you is a completely different question -- it needs
// the same tag seen in several places over hours -- and this device says so on
// the screen rather than raising an alarm it has not earned.

#pragma once

#include <cstdint>

#include "ble/advert.h"

namespace orthrus::modules {

class Proximity {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Detail };

    static constexpr uint8_t kMaxDevices = 24;

    struct Device {
        uint8_t  addr[ble::kAddrLen] = {0};   // most significant byte first
        bool     randomAddress = false;
        ble::AddressKind addrKind = ble::AddressKind::Unknown;

        char     name[ble::kNameBuf] = {0};
        bool     hasName = false;

        ble::Kind kind = ble::Kind::Generic;
        uint16_t  companyId  = 0;
        bool      hasCompany = false;
        uint16_t  service    = 0;
        bool      hasService = false;

        int8_t   rssi     = 0;
        int8_t   bestRssi = -127;
        int8_t   txPower    = 0;
        bool     hasTxPower = false;

        uint32_t sightings   = 0;
        uint32_t firstSeenMs = 0;
        uint32_t lastSeenMs  = 0;
        bool     logged      = false;
    };

    void drain();
    int  find(const uint8_t addr[ble::kAddrLen]) const;
    void ingest(const uint8_t addr[ble::kAddrLen], bool randomAddress, int8_t rssi,
                const uint8_t* payload, size_t payloadLen);

    void drawList();
    void drawDetail();
    bool handleKeys();

    // Visible index -> device index, honouring the tracker filter.
    int  visibleCount() const;
    int  visibleAt(int i) const;

    Device  devices_[kMaxDevices];
    uint8_t count_ = 0;

    uint32_t trackersSeen_ = 0;

    bool trackersOnly_ = false;
    bool activeScan_   = false;

    int  selected_ = 0;
    int  scroll_   = 0;
    View view_     = View::List;

    uint32_t lastDrawMs_ = 0;
    uint32_t enteredMs_  = 0;
};

}  // namespace orthrus::modules
