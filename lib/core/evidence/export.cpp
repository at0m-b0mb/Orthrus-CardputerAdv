#include "export.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace orthrus::evidence {
namespace {

// Appends to a bounded buffer, tracking overflow rather than pretending.
struct Writer {
    char*  out;
    size_t cap;
    size_t used = 0;
    bool   overflowed = false;

    void put(const char* s) {
        if (overflowed || s == nullptr) return;
        const size_t n = std::strlen(s);
        if (used + n + 1 > cap) {
            overflowed = true;
            return;
        }
        std::memcpy(out + used, s, n);
        used += n;
        out[used] = '\0';
    }

    size_t finish() {
        if (cap == 0) return 0;
        out[overflowed ? 0 : used] = '\0';
        return overflowed ? 0 : used;
    }
};

}  // namespace

bool findField(const char* detail, const char* key, char* out, size_t cap) {
    if (detail == nullptr || key == nullptr || out == nullptr || cap == 0) return false;
    out[0] = '\0';

    const size_t keyLen = std::strlen(key);
    if (keyLen == 0) return false;

    for (const char* p = detail; *p; p++) {
        // Must match at a token boundary, or "lat=" would also match "flat=".
        if (p != detail && p[-1] != ' ') continue;
        if (std::strncmp(p, key, keyLen) != 0) continue;
        if (p[keyLen] != '=') continue;

        const char* v = p + keyLen + 1;
        size_t n = 0;
        while (v[n] && v[n] != ' ' && n + 1 < cap) n++;
        std::memcpy(out, v, n);
        out[n] = '\0';
        return n > 0;
    }
    return false;
}

Position positionOf(const Record& r) {
    Position p;
    char lat[24], lon[24];
    if (!findField(r.detail, "lat", lat, sizeof(lat))) return p;
    if (!findField(r.detail, "lon", lon, sizeof(lon))) return p;

    char* endLat = nullptr;
    char* endLon = nullptr;
    const double la = std::strtod(lat, &endLat);
    const double lo = std::strtod(lon, &endLon);
    if (endLat == lat || endLon == lon) return p;

    // 0,0 is in the Gulf of Guinea. It is far more often an uninitialised
    // struct than a real fix, and a map full of placemarks there is worse than
    // no map, so it is refused.
    if (la == 0.0 && lo == 0.0) return p;
    if (la < -90.0 || la > 90.0 || lo < -180.0 || lo > 180.0) return p;

    p.valid = true;
    p.lat   = la;
    p.lon   = lo;
    return p;
}

size_t escapeXml(const char* in, char* out, size_t cap) {
    if (out == nullptr || cap == 0) return 0;
    if (in == nullptr) {
        out[0] = '\0';
        return 0;
    }

    size_t used = 0;
    for (const char* p = in; *p; p++) {
        const char* rep = nullptr;
        char one[2] = {*p, '\0'};

        switch (*p) {
            case '&':  rep = "&amp;";  break;
            case '<':  rep = "&lt;";   break;
            case '>':  rep = "&gt;";   break;
            case '"':  rep = "&quot;"; break;
            case '\'': rep = "&apos;"; break;
            default:
                // Control characters have no legal place in XML character data
                // and some parsers reject the whole document over one. Drop
                // them rather than emit an unopenable file.
                if (static_cast<unsigned char>(*p) < 0x20) continue;
                rep = one;
                break;
        }

        const size_t n = std::strlen(rep);
        if (used + n + 1 > cap) {
            out[used] = '\0';
            return cap - 1;  // signals truncation
        }
        std::memcpy(out + used, rep, n);
        used += n;
    }
    out[used] = '\0';
    return used;
}

size_t sanitiseText(const char* in, char* out, size_t cap) {
    if (out == nullptr || cap == 0) return 0;
    if (in == nullptr) { out[0] = '\0'; return 0; }

    size_t n = 0;
    for (const char* p = in; *p && n + 1 < cap; p++) {
        const unsigned char c = static_cast<unsigned char>(*p);
        out[n++] = (c < 0x20 || c == 0x7F) ? ' ' : *p;
    }
    out[n] = '\0';
    return n;
}

size_t csvHeader(char* out, size_t cap) {
    Writer w{out, cap};
    w.put("seq,time_ms,kind,detail,digest\n");
    return w.finish();
}

size_t csvRow(char* out, size_t cap, const Record& r,
              const uint8_t digest[crypto::kSha256DigestLen]) {
    char hex[65] = {0};
    if (digest != nullptr) crypto::toHex(digest, hex);

    // Control bytes go first: a newline in a detail string would end the record
    // half way through and let the rest masquerade as a new row.
    char clean[kDetailLen];
    sanitiseText(r.detail, clean, sizeof(clean));

    // Then quoted with its own quotes doubled, per RFC 4180, so a comma or a
    // quote in a payload fragment cannot shift the columns.
    char quoted[kDetailLen * 2 + 4];
    size_t q = 0;
    quoted[q++] = '"';
    for (size_t i = 0; i < kDetailLen && clean[i]; i++) {
        if (q + 3 >= sizeof(quoted)) break;
        if (clean[i] == '"') quoted[q++] = '"';
        quoted[q++] = clean[i];
    }
    quoted[q++] = '"';
    quoted[q]   = '\0';

    char line[kDetailLen * 2 + 128];
    const int n = std::snprintf(line, sizeof(line), "%lu,%lu,%s,%s,%s\n",
                                static_cast<unsigned long>(r.seq),
                                static_cast<unsigned long>(r.timeMs),
                                recordKindName(r.kind), quoted, hex);
    if (n < 0) return 0;

    Writer w{out, cap};
    w.put(line);
    return w.finish();
}

size_t kmlHeader(char* out, size_t cap, const char* title) {
    char safeTitle[128];
    escapeXml(title, safeTitle, sizeof(safeTitle));

    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n"
        "<Document>\n"
        "  <name>%s</name>\n"
        "  <description>Orthrus survey. Positions are where the device was "
        "standing when the sighting was recorded, not where the transmitter "
        "is.</description>\n",
        safeTitle);

    Writer w{out, cap};
    w.put(buf);
    return w.finish();
}

size_t kmlPlacemark(char* out, size_t cap, const Record& r, const Position& p) {
    if (!p.valid) return 0;

    char name[64] = {0};
    if (!findField(r.detail, "dev", name, sizeof(name)))
        if (!findField(r.detail, "uid", name, sizeof(name)))
            std::snprintf(name, sizeof(name), "record %lu",
                          static_cast<unsigned long>(r.seq));

    char safeName[160];
    char safeDetail[kDetailLen * 6 + 8];
    escapeXml(name, safeName, sizeof(safeName));
    escapeXml(r.detail, safeDetail, sizeof(safeDetail));

    char buf[kDetailLen * 6 + 512];
    std::snprintf(buf, sizeof(buf),
        "  <Placemark>\n"
        "    <name>%s</name>\n"
        "    <description>%s</description>\n"
        "    <Point><coordinates>%.6f,%.6f,0</coordinates></Point>\n"
        "  </Placemark>\n",
        safeName, safeDetail, p.lon, p.lat);  // KML is lon,lat -- not lat,lon

    Writer w{out, cap};
    w.put(buf);
    return w.finish();
}

size_t kmlFooter(char* out, size_t cap) {
    Writer w{out, cap};
    w.put("</Document>\n</kml>\n");
    return w.finish();
}

bool csvField(const char* line, int index, char* out, size_t cap) {
    if (line == nullptr || out == nullptr || cap == 0 || index < 0) return false;
    out[0] = '\0';

    int    field  = 0;
    bool   quoted = false;
    size_t n      = 0;

    for (const char* p = line; *p && *p != '\n' && *p != '\r'; p++) {
        if (quoted) {
            if (*p == '"') {
                // A doubled quote inside a quoted field is one literal quote.
                if (p[1] == '"') {
                    if (field == index && n + 1 < cap) out[n++] = '"';
                    p++;
                } else {
                    quoted = false;
                }
                continue;
            }
            if (field == index && n + 1 < cap) out[n++] = *p;
            continue;
        }

        if (*p == '"') { quoted = true; continue; }
        if (*p == ',') {
            if (field == index) { out[n] = '\0'; return true; }
            field++;
            continue;
        }
        if (field == index && n + 1 < cap) out[n++] = *p;
    }

    out[n] = '\0';
    return field == index;
}

}  // namespace orthrus::evidence
