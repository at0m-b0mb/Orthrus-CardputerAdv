#include "gnss.h"

#include <Arduino.h>

#include "board.h"

namespace orthrus::hal {

bool Gnss::begin() {
    if (started_) return true;
    Serial2.begin(board::kGpsBaud, SERIAL_8N1, board::kGpsRx, board::kGpsTx);
    started_ = true;
    return true;
}

void Gnss::pump() {
    if (!started_) return;

    // Bounded per call. The module emits a burst of NMEA once a second; without
    // a cap a busy burst could hold the UI loop for milliseconds at a time.
    int budget = 256;
    while (Serial2.available() && budget-- > 0) {
        const char c = static_cast<char>(Serial2.read());
        bytes_++;
        lastByteMs_ = millis();
        if (gps_.encode(c)) sentences_++;
    }
}

Gnss& sharedGnss() {
    static Gnss instance;
    return instance;
}

}  // namespace orthrus::hal
