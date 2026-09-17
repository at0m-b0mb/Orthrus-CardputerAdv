// Positions, and how much to believe them.
//
// A red team report that says "the reader is at 51.504821, -0.128476" is
// claiming about a centimetre of precision from a receiver that does not have
// it. This file exists so the device can show a position AND the radius it is
// actually good to, rather than six decimal places of false confidence.
//
// The estimate here is deliberately conservative and its basis is written down:
// HDOP multiplied by a nominal single-frequency user range error. It is an
// order-of-magnitude statement, not a survey.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::geo {

// Degrees / minutes / seconds, with the hemisphere letter.
//
// `degreeMark` is a parameter because the on-device face draws its degree glyph
// at 0xF8 rather than at the Latin-1 codepoint, and hard-coding either one puts
// a wrong character on either the screen or in an exported file.
//
// Returns characters written, excluding the NUL; 0 if it does not fit, and the
// buffer is left empty rather than half-written.
size_t formatDms(double degrees, bool isLatitude, char* out, size_t cap,
                 const char* degreeMark = "\xF8");

// How good the satellite geometry is. These bands are the conventional ones and
// they describe GEOMETRY, not accuracy: a receiver with perfect geometry under
// a metal roof still has a bad fix.
enum class Geometry : uint8_t {
    Unknown = 0,   // no HDOP reported yet
    Ideal,         // < 1
    Excellent,     // 1 - 2
    Good,          // 2 - 5
    Moderate,      // 5 - 10
    Poor,          // 10 - 20
    Unusable,      // > 20
};

Geometry geometryFor(double hdop);
const char* geometryName(Geometry g);

// A conservative horizontal error radius in metres, from HDOP.
//
// HDOP is a multiplier on the receiver's ranging error, so the estimate is
// hdop * UERE. The UERE used here is 5 m, which is a normal figure for an
// uncorrected single-frequency consumer receiver -- the class of chip on this
// cap. The result is rounded UP and floored at the UERE, because a device that
// reports a two metre radius it cannot deliver is worse than one that reports
// five.
//
// Returns 0 when there is no HDOP to work from. Zero means "unknown", and the
// caller must show it as unknown rather than as perfect.
uint16_t estimatedErrorMeters(double hdop);

inline constexpr double kNominalUereMeters = 5.0;

// Great-circle distance in metres between two positions.
//
// Haversine on a spherical earth: good to about 0.5% anywhere, which is far
// inside the receiver's own error and therefore not the limiting factor.
double distanceMeters(double lat1, double lon1, double lat2, double lon2);

// True when a latitude/longitude pair is inside the valid range AND is not the
// null island (0, 0).
//
// Exactly (0, 0) is in the Gulf of Guinea and is overwhelmingly more likely to
// be an uninitialised struct than a real fix. Logging it as a waypoint puts a
// false pin in the client's map.
bool plausible(double lat, double lon);

}  // namespace orthrus::geo
