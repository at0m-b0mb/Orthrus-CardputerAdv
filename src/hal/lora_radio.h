// SX1262 receive path for LoRaWAN PHY sniffing.
//
// Receive-only in this build: nothing here calls a transmit primitive. The
// active-test modules will sit alongside this rather than inside it, so the
// listening path stays something you can read top to bottom and be sure of.

#pragma once

#include <RadioLib.h>

#include <cstdint>

#include "lorawan/census.h"

namespace orthrus::hal {

struct RadioConfig {
    uint32_t freqHz = 868100000;
    uint8_t  sf     = 7;
    uint16_t bwKhz  = 125;
    uint8_t  cr     = 5;  // 4/5
};

// Counters the operator should be able to see, because "nothing yet" and
// "plenty arriving but none of it decodes" are very different situations and a
// scanner that shows the same empty list for both is lying by omission.
struct RadioStats {
    uint32_t packets    = 0;
    uint32_t crcErrors  = 0;
    uint32_t tooLong    = 0;
    uint32_t otherErrors = 0;
};

class LoraRadio {
public:
    bool begin();
    bool configure(const RadioConfig& cfg);
    bool listen();

    // Non-blocking. Returns the payload length when a frame arrived, 0 when
    // nothing is waiting, and -1 when something arrived but could not be read.
    int poll(uint8_t* buf, size_t cap, lorawan::RxMeta& meta);

    float instantRssi();

    // Drop the receiver to standby. Called when the operator leaves the module.
    void idle();

    const RadioConfig& config() const { return cfg_; }
    const RadioStats&  stats() const { return stats_; }
    const char*        lastError() const { return lastError_; }
    bool               ready() const { return ready_; }

private:
    RadioConfig cfg_{};
    RadioStats  stats_{};
    bool        ready_     = false;
    const char* lastError_ = "";
};

}  // namespace orthrus::hal
