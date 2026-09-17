// Bluetooth Low Energy advertisements, and what they actually prove.
//
// WHAT AN ADVERT IS
//
// A BLE device that wants to be found shouts a small packet, several times a
// second, to nobody in particular. It is unencrypted, unauthenticated and
// anyone within range can hear it. That is not a flaw -- it is how being
// discoverable works -- but it means every phone, earbud and luggage tag in a
// room is continuously announcing something about itself.
//
// WHAT THIS FILE REFUSES TO DO
//
// It does not guess at device types from names. "Living Room TV" is a string
// somebody typed, and half the trackers in the world are called "iPhone". Every
// classification here is drawn from a field whose meaning is assigned by a
// registry or by a published protocol, and anything else comes back Generic.
//
// AND THE BIG ONE: seeing a tracker's advert does NOT mean it is following you.
// A Find My advert means an Apple device is in offline-finding mode somewhere
// within about ten metres. Establishing that one is FOLLOWING somebody needs
// the same device seen in several places over time, which is a different
// question, and this device says so rather than raising an alarm.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::ble {

inline constexpr size_t kNameMax     = 24;
inline constexpr size_t kNameBuf     = kNameMax + 1;
inline constexpr size_t kMaxServices = 6;
inline constexpr size_t kAddrLen     = 6;

// Assigned numbers used below. Each is a registry entry, not a guess.
inline constexpr uint16_t kCompanyApple     = 0x004C;
inline constexpr uint16_t kCompanyMicrosoft = 0x0006;
inline constexpr uint16_t kCompanySamsung   = 0x0075;
inline constexpr uint16_t kCompanyGoogle    = 0x00E0;
inline constexpr uint16_t kCompanyTile      = 0x0157;

inline constexpr uint16_t kServiceTile      = 0xFEED;  // Tile, Inc.
inline constexpr uint16_t kServiceSamsung   = 0xFD5A;  // Samsung SmartThings/Tag
inline constexpr uint16_t kServiceFastPair  = 0xFE2C;  // Google Fast Pair
inline constexpr uint16_t kServiceEddystone = 0xFEAA;  // Google Eddystone

// Apple's manufacturer-data subtypes, from the published Continuity work.
inline constexpr uint8_t kAppleIBeacon      = 0x02;
inline constexpr uint8_t kAppleNearby       = 0x10;
inline constexpr uint8_t kAppleFindMy       = 0x12;
inline constexpr uint8_t kAppleProximityPair = 0x07;

struct Advert {
    char     name[kNameBuf] = {0};
    bool     hasName        = false;
    bool     nameShortened  = false;

    uint16_t companyId  = 0;
    bool     hasCompany = false;

    // Apple packs a subtype and a length in front of its payload. Kept
    // separately because it is the field that distinguishes a luggage tag from
    // a pair of earbuds, and both are company 0x004C.
    uint8_t appleType = 0;
    uint8_t appleLen  = 0;

    uint16_t services[kMaxServices] = {0};
    uint8_t  serviceCount = 0;

    int8_t txPower    = 0;
    bool   hasTxPower = false;

    uint8_t flags    = 0;
    bool    hasFlags = false;

    // An AD structure claimed more bytes than the packet held. The fields
    // parsed before it are still good; the rest is not, and the difference is
    // reported rather than smoothed over.
    bool truncated = false;

    bool hasService(uint16_t uuid) const;
};

// Parses the AD structures of an advertisement or scan response.
bool parseAdvert(const uint8_t* data, size_t len, Advert& out);

// ---- addresses ---------------------------------------------------------------

enum class AddressKind : uint8_t {
    Public = 0,             // a real, permanent, registry-assigned address
    RandomStatic,           // random, but fixed until the device reboots
    ResolvablePrivate,      // rotates every ~15 minutes; deliberately untrackable
    NonResolvablePrivate,   // rotates, and nobody can resolve it at all
    Unknown,
};

// `addr` is most-significant byte first, which is how it is written down and
// displayed. The two top bits of that byte are what carry the kind.
AddressKind addressKind(const uint8_t addr[kAddrLen], bool randomAddress);
const char* addressKindName(AddressKind k);

// Whether this address can be followed from one sighting to the next at all. A
// rotating address cannot, which is the single most useful privacy fact about
// any device on the list.
bool addressIsStable(AddressKind k);

// ---- classification ----------------------------------------------------------

enum class Kind : uint8_t {
    Generic = 0,
    Continuity,     // an Apple device announcing itself to nearby Apple devices
    FindMy,         // Apple offline-finding: AirTag, or anything in that network
    TileTracker,
    SamsungTag,
    FastPair,       // a Google Fast Pair accessory advertising for pairing
    IBeacon,
    Eddystone,
};

Kind classify(const Advert& a);
const char* kindName(Kind k);
const char* kindDetail(Kind k);

// True for the classifications that identify an item-finding tag. Deliberately
// narrow: a beacon in a shop window is not a tracker, and calling it one
// teaches an operator to ignore the label.
bool isTracker(Kind k);

// Company identifier to a readable name, for the handful worth naming. Returns
// nullptr when the identifier is not in the table, so the caller shows the
// number rather than inventing a vendor.
const char* companyName(uint16_t id);

// ---- range -------------------------------------------------------------------

enum class Proximity : uint8_t { Unknown = 0, Immediate, Near, Far, Distant };

// A coarse band, never a distance in metres.
//
// Turning RSSI into metres needs a path-loss exponent that depends on the walls
// between you and the device, and indoors the answer is routinely wrong by a
// factor of three. A number that precise would be believed; a band is not.
Proximity proximityFor(int rssi, bool haveTxPower, int8_t txPowerAt1m);
const char* proximityName(Proximity p);

}  // namespace orthrus::ble
