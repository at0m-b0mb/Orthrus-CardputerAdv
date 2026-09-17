// ATGM336H GNSS on the LoRa cap.
//
// Non-blocking by construction: pump() drains whatever bytes have arrived and
// returns immediately. A GPS that blocks a UI loop waiting for a fix is a GPS
// that makes the whole device feel broken, and indoors a fix may never come.
//
// Exposed deliberately: `alive()` is true as soon as NMEA is parsing, long
// before there is a position. That distinction matters on screen -- "receiving,
// no fix yet" is a completely different thing from "nothing plugged in", and
// showing them the same way is what makes a working device look dead.

#pragma once

#include <TinyGPSPlus.h>

#include <cstdint>

namespace orthrus::hal {

class Gnss {
public:
    bool begin();

    // Drains the UART. Cheap; call it every loop.
    void pump();

    bool alive() const { return sentences_ > 0; }

    // Not const, deliberately. TinyGPSPlus clears each field's "updated" flag
    // when you read its value, so these accessors genuinely mutate state and
    // pretending otherwise with a mutable member would hide that.
    bool hasFix() { return gps_.location.isValid() && gps_.location.age() < 5000; }

    uint32_t satellites() {
        return gps_.satellites.isValid() ? gps_.satellites.value() : 0;
    }
    double latitude() { return gps_.location.lat(); }
    double longitude() { return gps_.location.lng(); }

    bool hasTime() { return gps_.time.isValid() && gps_.date.isValid(); }
    uint8_t hour() { return gps_.time.hour(); }
    uint8_t minute() { return gps_.time.minute(); }
    uint8_t second() { return gps_.time.second(); }
    uint16_t year() { return gps_.date.year(); }
    uint8_t month() { return gps_.date.month(); }
    uint8_t day() { return gps_.date.day(); }

    // How stale the position is, in milliseconds. A fix that stopped updating
    // thirty seconds ago is not a fix, however valid the last one looked.
    uint32_t locationAgeMs() { return gps_.location.age(); }

    double altitudeMeters() {
        return gps_.altitude.isValid() ? gps_.altitude.meters() : 0.0;
    }
    bool hasAltitude() { return gps_.altitude.isValid(); }

    double speedKmph() { return gps_.speed.isValid() ? gps_.speed.kmph() : 0.0; }
    bool hasSpeed() { return gps_.speed.isValid(); }

    double courseDegrees() {
        return gps_.course.isValid() ? gps_.course.deg() : 0.0;
    }
    bool hasCourse() { return gps_.course.isValid(); }

    // Sentences the parser rejected. A receiver that is talking but failing its
    // own checksums is a wiring problem, not a sky problem, and the two look
    // identical if you only count good sentences.
    uint32_t checksumFailures() { return gps_.failedChecksum(); }

    // Horizontal dilution of precision: how much the satellite geometry is
    // degrading the fix. Under 2 is good, over 5 is barely worth having.
    double hdop() { return gps_.hdop.isValid() ? gps_.hdop.hdop() : 0.0; }

    uint32_t sentences() const { return sentences_; }
    uint32_t bytes() const { return bytes_; }
    uint32_t lastByteMs() const { return lastByteMs_; }

private:
    TinyGPSPlus gps_;
    uint32_t    sentences_  = 0;
    uint32_t    bytes_      = 0;
    uint32_t    lastByteMs_ = 0;
    bool        started_    = false;
};

// Same reasoning as sharedRadio(): two Gnss objects would both drain Serial2
// and steal each other's bytes, so neither would ever see a complete sentence.
Gnss& sharedGnss();

}  // namespace orthrus::hal
