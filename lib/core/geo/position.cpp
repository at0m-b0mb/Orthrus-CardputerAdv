#include "geo/position.h"

#include <cmath>
#include <cstdio>
#include <cstring>

namespace orthrus::geo {

namespace {

constexpr double kEarthRadiusM = 6371008.8;  // IUGG mean radius
constexpr double kPi = 3.14159265358979323846;

double toRadians(double deg) { return deg * kPi / 180.0; }

}  // namespace

size_t formatDms(double degrees, bool isLatitude, char* out, size_t cap,
                 const char* degreeMark) {
    if (out == nullptr || cap == 0) return 0;
    out[0] = '\0';
    if (degreeMark == nullptr) degreeMark = "";

    if (std::isnan(degrees) || std::isinf(degrees)) return 0;

    const char hemi = isLatitude ? (degrees < 0 ? 'S' : 'N')
                                 : (degrees < 0 ? 'W' : 'E');
    double v = std::fabs(degrees);

    const double limit = isLatitude ? 90.0 : 180.0;
    if (v > limit) return 0;

    unsigned deg = static_cast<unsigned>(v);
    double   rem = (v - deg) * 60.0;
    unsigned min = static_cast<unsigned>(rem);
    double   sec = (rem - min) * 60.0;

    // Rounding carries. 59.9996 seconds prints as "60.0" at one decimal place,
    // which is not a time anybody writes down -- and at 59 minutes it has to
    // carry all the way into the degrees. Doing the carry here rather than
    // leaving snprintf to produce 51d59'60.0" is the whole reason this is not
    // three lines of printf.
    if (sec >= 59.95) {
        sec = 0.0;
        min++;
        if (min >= 60) {
            min = 0;
            deg++;
        }
    }

    char buf[32];
    const int n = std::snprintf(buf, sizeof(buf), "%u%s%02u'%04.1f\"%c", deg,
                                degreeMark, min, sec, hemi);
    if (n <= 0 || static_cast<size_t>(n) >= cap) return 0;

    std::memcpy(out, buf, static_cast<size_t>(n) + 1);
    return static_cast<size_t>(n);
}

Geometry geometryFor(double hdop) {
    if (!(hdop > 0.0)) return Geometry::Unknown;   // also catches NaN
    if (hdop < 1.0)  return Geometry::Ideal;
    if (hdop < 2.0)  return Geometry::Excellent;
    if (hdop < 5.0)  return Geometry::Good;
    if (hdop < 10.0) return Geometry::Moderate;
    if (hdop < 20.0) return Geometry::Poor;
    return Geometry::Unusable;
}

const char* geometryName(Geometry g) {
    switch (g) {
        case Geometry::Unknown:   return "unknown";
        case Geometry::Ideal:     return "ideal";
        case Geometry::Excellent: return "excellent";
        case Geometry::Good:      return "good";
        case Geometry::Moderate:  return "moderate";
        case Geometry::Poor:      return "poor";
        case Geometry::Unusable:  return "unusable";
    }
    return "unknown";
}

uint16_t estimatedErrorMeters(double hdop) {
    if (!(hdop > 0.0)) return 0;   // unknown, and the caller must say so

    double metres = hdop * kNominalUereMeters;
    if (metres < kNominalUereMeters) metres = kNominalUereMeters;

    // Rounded up. An estimate that rounds down is an estimate that sometimes
    // excludes the true position, which defeats the point of quoting a radius.
    const double up = std::ceil(metres);
    if (up > 9999.0) return 9999;
    return static_cast<uint16_t>(up);
}

double distanceMeters(double lat1, double lon1, double lat2, double lon2) {
    const double p1 = toRadians(lat1);
    const double p2 = toRadians(lat2);
    const double dp = toRadians(lat2 - lat1);
    const double dl = toRadians(lon2 - lon1);

    const double a = std::sin(dp / 2) * std::sin(dp / 2) +
                     std::cos(p1) * std::cos(p2) * std::sin(dl / 2) * std::sin(dl / 2);
    const double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1 - a));
    return kEarthRadiusM * c;
}

bool plausible(double lat, double lon) {
    if (std::isnan(lat) || std::isnan(lon)) return false;
    if (lat < -90.0 || lat > 90.0) return false;
    if (lon < -180.0 || lon > 180.0) return false;

    // Null island. Far more likely to be a struct nobody filled in than a boat
    // in the Gulf of Guinea, and a false pin on a client's map is worse than a
    // missing one.
    if (lat == 0.0 && lon == 0.0) return false;
    return true;
}

}  // namespace orthrus::geo
