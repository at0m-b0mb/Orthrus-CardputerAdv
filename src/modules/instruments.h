// Instruments: everything the device can currently sense, on one screen.
//
// Exists because of a real complaint from the field: open a surface and nothing
// appears to happen. Airspace only moved when a LoRaWAN frame arrived, and with
// no gateway nearby that is never. This screen is the opposite -- every line on
// it changes on its own, so "is this thing working?" is answered in one glance
// before any protocol work starts.
//
// It is also genuinely useful: battery before a long walk, GPS lock before
// geotagging findings, the radio's own noise floor before blaming the antenna.

#pragma once

#include <cstdint>

#include "hal/gnss.h"
#include "hal/lora_radio.h"

namespace orthrus::modules {

class Instruments {
public:
    bool begin();
    void run();

private:
    void sample();
    void draw();
    void drawBubble(int cx, int cy, int r);

    hal::Gnss&      gnss_  = hal::sharedGnss();
    hal::LoraRadio& radio_ = hal::sharedRadio();

    bool  radioUp_ = false;
    float rssi_    = 0.0f;
    float ax_ = 0, ay_ = 0, az_ = 0;

    uint32_t lastSampleMs_ = 0;
    uint32_t lastDrawMs_   = 0;
    uint32_t startedMs_    = 0;
    uint32_t minHeap_      = 0;
};

}  // namespace orthrus::modules
