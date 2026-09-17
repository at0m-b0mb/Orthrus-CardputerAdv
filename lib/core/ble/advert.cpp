#include "ble/advert.h"

#include <cstring>

namespace orthrus::ble {

namespace {

// AD types, from the Bluetooth assigned numbers.
constexpr uint8_t kAdFlags          = 0x01;
constexpr uint8_t kAdService16Part  = 0x02;
constexpr uint8_t kAdService16All   = 0x03;
constexpr uint8_t kAdNameShort      = 0x08;
constexpr uint8_t kAdNameComplete   = 0x09;
constexpr uint8_t kAdTxPower        = 0x0A;
constexpr uint8_t kAdServiceData16  = 0x16;
constexpr uint8_t kAdManufacturer   = 0xFF;

uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

struct Company {
    uint16_t    id;
    const char* name;
};

// Only the identifiers worth naming on a 240 px screen. Anything absent is
// shown as its number, which is honest, rather than as a vendor we guessed.
constexpr Company kCompanies[] = {
    {0x004C, "Apple"},
    {0x0006, "Microsoft"},
    {0x0075, "Samsung"},
    {0x00E0, "Google"},
    {0x0157, "Tile"},
    {0x0059, "Nordic"},
    {0x0087, "Garmin"},
    {0x000F, "Broadcom"},
    {0x0171, "Amazon"},
    {0x02E5, "Espressif"},
    {0x038F, "Xiaomi"},
    {0x0499, "Ruuvi"},
};

}  // namespace

bool Advert::hasService(uint16_t uuid) const {
    for (uint8_t i = 0; i < serviceCount; i++)
        if (services[i] == uuid) return true;
    return false;
}

bool parseAdvert(const uint8_t* data, size_t len, Advert& out) {
    out = Advert{};
    if (data == nullptr) return false;

    size_t i = 0;
    while (i < len) {
        const uint8_t adLen = data[i];

        // A zero length is the standard end-of-data padding, not an error.
        if (adLen == 0) break;

        // A structure that claims more than the packet holds. Everything parsed
        // so far is still good, so it is kept and the overrun is flagged --
        // discarding a valid name because the last field was malformed would
        // hand an attacker a way to hide from the list.
        if (i + 1 + adLen > len) {
            out.truncated = true;
            break;
        }

        const uint8_t  type    = data[i + 1];
        const uint8_t* payload = data + i + 2;
        const uint8_t  plen    = static_cast<uint8_t>(adLen - 1);

        switch (type) {
            case kAdFlags:
                if (plen >= 1) {
                    out.flags    = payload[0];
                    out.hasFlags = true;
                }
                break;

            case kAdNameShort:
            case kAdNameComplete: {
                const size_t n = plen > kNameMax ? kNameMax : plen;
                std::memcpy(out.name, payload, n);
                out.name[n] = '\0';

                // A name is 24 arbitrary bytes somebody typed. Control
                // characters in it would corrupt any line it is written to, so
                // they are replaced here rather than at every call site.
                for (size_t k = 0; k < n; k++) {
                    const unsigned char c = static_cast<unsigned char>(out.name[k]);
                    if (c < 0x20 || c == 0x7F) out.name[k] = ' ';
                }
                out.hasName       = true;
                out.nameShortened = (type == kAdNameShort);
                break;
            }

            case kAdTxPower:
                if (plen >= 1) {
                    out.txPower    = static_cast<int8_t>(payload[0]);
                    out.hasTxPower = true;
                }
                break;

            case kAdService16Part:
            case kAdService16All:
                for (uint8_t k = 0; k + 1 < plen && out.serviceCount < kMaxServices;
                     k += 2) {
                    out.services[out.serviceCount++] = le16(payload + k);
                }
                break;

            case kAdServiceData16:
                // Service data leads with the UUID it belongs to. Trackers are
                // identified by that UUID, and several of them only ever put it
                // here rather than in a service list.
                if (plen >= 2 && out.serviceCount < kMaxServices)
                    out.services[out.serviceCount++] = le16(payload);
                break;

            case kAdManufacturer:
                if (plen >= 2) {
                    out.companyId  = le16(payload);
                    out.hasCompany = true;
                    // Apple puts a subtype and a length in front of its payload.
                    // It is what separates a luggage tag from earbuds, and both
                    // are company 0x004C.
                    if (out.companyId == kCompanyApple && plen >= 4) {
                        out.appleType = payload[2];
                        out.appleLen  = payload[3];
                    }
                }
                break;

            default:
                break;
        }

        i += 1 + adLen;
    }

    return true;
}

// ---- addresses ---------------------------------------------------------------

AddressKind addressKind(const uint8_t addr[kAddrLen], bool randomAddress) {
    if (addr == nullptr) return AddressKind::Unknown;
    if (!randomAddress) return AddressKind::Public;

    // The two most significant bits of the most significant byte carry the
    // kind. Reading them off the wrong end of the address is the classic bug
    // here, which is why the header states the byte order.
    switch ((addr[0] >> 6) & 0x03) {
        case 0x03: return AddressKind::RandomStatic;
        case 0x01: return AddressKind::ResolvablePrivate;
        case 0x00: return AddressKind::NonResolvablePrivate;
        default:   return AddressKind::Unknown;   // 0b10 is reserved
    }
}

const char* addressKindName(AddressKind k) {
    switch (k) {
        case AddressKind::Public:               return "public";
        case AddressKind::RandomStatic:         return "static";
        case AddressKind::ResolvablePrivate:    return "rotating";
        case AddressKind::NonResolvablePrivate: return "rotating";
        case AddressKind::Unknown:              return "unknown";
    }
    return "unknown";
}

bool addressIsStable(AddressKind k) {
    return k == AddressKind::Public || k == AddressKind::RandomStatic;
}

// ---- classification ----------------------------------------------------------

Kind classify(const Advert& a) {
    // A DELIBERATE DIFFERENCE FROM GhostTag, WHICH IS OTHERWISE THE ORACLE HERE
    //
    // Every constant below was checked against GhostTag's ESP32 companion,
    // which is proven against real AirTags, Tiles and SmartTags: company 0x004C
    // with subtype 0x12, service 0xFEED, service 0xFD5A. All agree.
    //
    // GhostTag additionally calls anything carrying Samsung's company id
    // (0x0075) a SmartTag. That is right for an anti-stalking alarm, where a
    // false positive costs a glance. It is wrong here, where isTracker() writes
    // a finding into an evidence log -- every Samsung phone, watch and pair of
    // earbuds advertises with that company id, and a report claiming a room
    // full of trackers is a report nobody reads twice.
    //
    // So Samsung is recognised by its SERVICE UUID only. Do not "fix" this to
    // match GhostTag.

    // Service UUIDs first: they are assigned to one owner and mean one thing.
    if (a.hasService(kServiceTile) || a.hasService(kServiceTileNew))
        return Kind::TileTracker;
    if (a.hasService(kServiceSamsung)) return Kind::SamsungTag;
    if (a.hasService(kServiceEddystone)) return Kind::Eddystone;
    if (a.hasService(kServiceFastPair)) return Kind::FastPair;

    if (a.hasCompany && a.companyId == kCompanyApple) {
        // iBeacon is checked by its length as well as its type: 0x02 with any
        // other length is not an iBeacon frame and should not be read as one.
        if (a.appleType == kAppleIBeacon && a.appleLen == 0x15) return Kind::IBeacon;
        if (a.appleType == kAppleFindMy) return Kind::FindMy;
        if (a.appleType == kAppleNearby || a.appleType == kAppleProximityPair)
            return Kind::Continuity;
    }

    return Kind::Generic;
}

const char* kindName(Kind k) {
    switch (k) {
        case Kind::Generic:     return "device";
        case Kind::Continuity:  return "Apple";
        case Kind::FindMy:      return "Find My";
        case Kind::TileTracker: return "Tile";
        case Kind::SamsungTag:  return "SmartTag";
        case Kind::FastPair:    return "Fast Pair";
        case Kind::IBeacon:     return "iBeacon";
        case Kind::Eddystone:   return "Eddystone";
    }
    return "device";
}

const char* kindDetail(Kind k) {
    switch (k) {
        case Kind::Generic:
            return "Advertising, with nothing in it that identifies what it is. "
                   "Most devices in any room look like this.";
        case Kind::Continuity:
            return "An Apple device announcing itself to nearby Apple devices. "
                   "A phone, a watch or earbuds -- not a tracker.";
        case Kind::FindMy:
            return "In Apple's offline-finding network: an AirTag, or anything "
                   "else in it. Present within range. NOT proof it is following "
                   "you -- that needs the same tag in several places over time.";
        case Kind::TileTracker:
            return "A Tile item finder. Present within range. Whether it belongs "
                   "here is a question this device cannot answer.";
        case Kind::SamsungTag:
            return "A Samsung SmartTag or SmartThings device. Present within "
                   "range, and nothing more than that.";
        case Kind::FastPair:
            return "A Google Fast Pair accessory advertising to be paired, which "
                   "usually means headphones in pairing mode.";
        case Kind::IBeacon:
            return "A fixed iBeacon: a shop, a museum, a car park. It broadcasts "
                   "a position, it does not record yours.";
        case Kind::Eddystone:
            return "An Eddystone beacon, the open equivalent of iBeacon. Fixed "
                   "infrastructure rather than anything personal.";
    }
    return "";
}

bool isTracker(Kind k) {
    return k == Kind::FindMy || k == Kind::TileTracker || k == Kind::SamsungTag;
}

const char* companyName(uint16_t id) {
    for (const auto& c : kCompanies)
        if (c.id == id) return c.name;
    return nullptr;
}

// ---- range -------------------------------------------------------------------

Proximity proximityFor(int rssi, bool haveTxPower, int8_t txPowerAt1m) {
    // A reading of exactly 0 is what a scanner reports when it has no RSSI at
    // all, not a device pressed against the antenna.
    if (rssi == 0 || rssi < -127 || rssi > 20) return Proximity::Unknown;

    // Without a calibrated transmit power there is nothing to compare against,
    // so the bands fall back to raw RSSI. They are deliberately generous: this
    // is a near/far answer, and pretending otherwise indoors is how people end
    // up searching the wrong room.
    const int reference = haveTxPower ? txPowerAt1m : -59;
    const int loss = reference - rssi;

    if (loss <= 5)  return Proximity::Immediate;   // within arm's reach
    if (loss <= 20) return Proximity::Near;        // same room
    if (loss <= 35) return Proximity::Far;         // through a wall or two
    return Proximity::Distant;
}

const char* proximityName(Proximity p) {
    switch (p) {
        case Proximity::Immediate: return "here";
        case Proximity::Near:      return "near";
        case Proximity::Far:       return "far";
        case Proximity::Distant:   return "distant";
        case Proximity::Unknown:   return "?";
    }
    return "?";
}

}  // namespace orthrus::ble
