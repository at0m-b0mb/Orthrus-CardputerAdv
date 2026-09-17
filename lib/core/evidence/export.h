// Turning an evidence log into something a client can open.
//
// Two formats, both produced without allocation and both bounds-checked:
//
//   CSV  -- the log itself, one record per line, digest included, so the chain
//           can be re-verified offline by anyone with the seed.
//   KML  -- geotagged sightings as placemarks, which opens in Google Earth and
//           is the artefact that makes an RF survey legible to someone who does
//           not read hex.
//
// XML escaping is the security-relevant part and is why this is a tested module
// rather than a few sprintf calls at the call site. Detail strings come from the
// air: a device name, an SSID, a payload fragment. A record containing
// "</name><Placemark>" would otherwise inject structure into the KML, and the
// same class of bug has been ruining log viewers for thirty years.

#pragma once

#include <cstddef>
#include <cstdint>

#include "chain.h"

namespace orthrus::evidence {

// A parsed position, if the record carried one. Sightings without a fix are
// still logged; they just cannot be placed on a map.
struct Position {
    bool   valid = false;
    double lat   = 0.0;
    double lon   = 0.0;
};

// Records carry structured detail as space-separated key=value pairs, e.g.
//   "dev=26011BDA rssi=-78 grade=F lat=51.5074 lon=-0.1278"
// Readable in the CSV as-is, and machine-readable for the map.
bool     findField(const char* detail, const char* key, char* out, size_t cap);
Position positionOf(const Record& r);

// Escapes text for XML character data. Returns the number of bytes written,
// never exceeding cap-1, and always NUL-terminates. Truncation is reported by
// returning cap-1 so a caller can notice rather than silently ship half a tag.
size_t escapeXml(const char* in, char* out, size_t cap);

// CSV. Returns bytes written (excluding the terminator), 0 if it did not fit.
size_t csvHeader(char* out, size_t cap);
size_t csvRow(char* out, size_t cap, const Record& r,
              const uint8_t digest[crypto::kSha256DigestLen]);

// KML. `title` and `seedHex` appear in the document description so an exported
// file identifies the session it came from.
size_t kmlHeader(char* out, size_t cap, const char* title);
size_t kmlPlacemark(char* out, size_t cap, const Record& r, const Position& p);
size_t kmlFooter(char* out, size_t cap);

// Reads field `index` (0-based) out of an RFC 4180 CSV line, honouring quoting
// and doubled quotes. Needed because the KML export re-reads the log the device
// wrote: the log file is the single source of truth, and re-parsing it is how
// the map and the evidence stay the same data.
bool csvField(const char* line, int index, char* out, size_t cap);

}  // namespace orthrus::evidence
