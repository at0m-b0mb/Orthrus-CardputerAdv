#include "ble/emulate.h"

#include <cstring>

namespace orthrus::ble {

namespace {

// AD types, from the Bluetooth assigned numbers. Repeated here rather than
// exported from advert.cpp because a builder and a parser agreeing by accident
// is the bug the round-trip tests exist to catch: if these drift, the tests
// stop round-tripping and say so.
constexpr uint8_t kAdFlags         = 0x01;
constexpr uint8_t kAdService16All  = 0x03;
constexpr uint8_t kAdNameComplete  = 0x09;
constexpr uint8_t kAdTxPower       = 0x0A;
constexpr uint8_t kAdServiceData16 = 0x16;
constexpr uint8_t kAdManufacturer  = 0xFF;

// LE General Discoverable, BR/EDR not supported. What every advertisement from
// a battery-powered Bluetooth-only device carries.
constexpr uint8_t kFlagsLeOnly = 0x06;

// Writes one AD structure: length, type, payload. The length byte counts the
// type byte as well as the payload, which is the single most commonly
// mis-written byte in the format.
//
// Returns 0 and writes nothing when it would not fit, so a caller that checks
// the total never emits a half-structure.
size_t putAd(uint8_t* out, size_t cap, uint8_t type, const uint8_t* payload,
             size_t plen) {
    const size_t total = plen + 2;
    if (out == nullptr || cap < total) return 0;
    out[0] = static_cast<uint8_t>(plen + 1);
    out[1] = type;
    if (plen) std::memcpy(out + 2, payload, plen);
    return total;
}

void putLe16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>(v >> 8);
}

// The same mix inject.cpp uses. Not a hash, and nothing depends on it being
// one: it only has to spread consecutive salts so a swarm does not look like a
// counter.
uint32_t mix(uint32_t x) {
    x = x * 2654435761u + 0x9E3779B9u;
    x ^= x >> 15;
    x *= 0x85EBCA6Bu;
    x ^= x >> 13;
    return x;
}

}  // namespace

void deriveIdentity(uint8_t* out, size_t len, uint32_t salt) {
    if (out == nullptr) return;
    uint32_t x = mix(salt);
    for (size_t i = 0; i < len; i++) {
        if ((i % 4) == 0) x = mix(x + static_cast<uint32_t>(i));
        out[i] = static_cast<uint8_t>((x >> (8 * (i % 4))) & 0xFF);
    }
}

void randomStaticAddress(uint8_t out[kAddrLen], uint32_t salt) {
    if (out == nullptr) return;
    deriveIdentity(out, kAddrLen, salt ^ 0x5A5AA5A5u);
    // Random static: the top two bits of the most significant byte are both
    // set. Anything else is a resolvable or non-resolvable private address,
    // which rotates -- and a swarm whose members rotate underneath it cannot
    // be counted by the thing being tested.
    out[0] = static_cast<uint8_t>(out[0] | 0xC0);
}

// ---- Apple Find My ----------------------------------------------------------

size_t buildFindMy(uint8_t* out, size_t cap, const uint8_t key[kFindMyKeyLen],
                   uint8_t status) {
    // Exactly 31 bytes, and no flags structure: that is what a non-connectable
    // undirected tracker advertisement looks like, and there is no room for
    // one anyway.
    //
    //   1E FF 4C 00 12 19 <status> <22 key bytes> <key bits> <hint>
    //
    // 0x12 is the Find My subtype and 0x19 is 25, the length of everything
    // after it. Both are read by the classifier, so getting either wrong turns
    // this into a generic Apple advertisement.
    if (out == nullptr || key == nullptr) return 0;
    if (cap < kAdvertMax) return 0;

    uint8_t payload[29];
    size_t i = 0;
    putLe16(payload + i, kCompanyApple); i += 2;
    payload[i++] = kAppleFindMy;
    payload[i++] = 0x19;                 // 25 bytes follow
    payload[i++] = status;
    std::memcpy(payload + i, key, kFindMyKeyLen);
    i += kFindMyKeyLen;
    // The two low bits of the public key's first byte, which a real tag sends
    // separately so a finder can reconstruct the full key.
    payload[i++] = static_cast<uint8_t>((key[0] >> 6) & 0x03);
    payload[i++] = 0x00;                 // hint: zero on a tag in the field

    const size_t n = putAd(out, cap, kAdManufacturer, payload, i);
    return n;
}

// ---- Tile -------------------------------------------------------------------

size_t buildTile(uint8_t* out, size_t cap, const uint8_t id[6],
                 uint16_t serviceUuid) {
    if (out == nullptr || id == nullptr) return 0;

    size_t n = 0;
    const uint8_t flags = kFlagsLeOnly;

    size_t w = putAd(out + n, cap - n, kAdFlags, &flags, 1);
    if (!w) return 0;
    n += w;

    uint8_t uuid[2];
    putLe16(uuid, serviceUuid);
    w = putAd(out + n, cap - n, kAdService16All, uuid, sizeof(uuid));
    if (!w) return 0;
    n += w;

    // Service data: the UUID again, then the identifier. The UUID is repeated
    // because several trackers put it ONLY here, and a classifier that reads
    // just the service list misses them -- so an emulation that omits it would
    // be testing a path real devices do not always use.
    uint8_t sd[8];
    putLe16(sd, serviceUuid);
    std::memcpy(sd + 2, id, 6);
    w = putAd(out + n, cap - n, kAdServiceData16, sd, sizeof(sd));
    if (!w) return 0;
    n += w;

    return n;
}

// ---- Samsung SmartTag -------------------------------------------------------

size_t buildSmartTag(uint8_t* out, size_t cap, const uint8_t id[6]) {
    if (out == nullptr || id == nullptr) return 0;

    size_t n = 0;
    const uint8_t flags = kFlagsLeOnly;

    size_t w = putAd(out + n, cap - n, kAdFlags, &flags, 1);
    if (!w) return 0;
    n += w;

    uint8_t uuid[2];
    putLe16(uuid, kServiceSamsung);
    w = putAd(out + n, cap - n, kAdService16All, uuid, sizeof(uuid));
    if (!w) return 0;
    n += w;

    // Service data: UUID, then a one-byte region marker and the privacy id a
    // real tag rotates. Not by company identifier -- see the header, and see
    // classify() in advert.cpp, which deliberately does not treat 0x0075 as a
    // tag because every Galaxy phone carries it.
    uint8_t sd[9];
    putLe16(sd, kServiceSamsung);
    sd[2] = 0x00;
    std::memcpy(sd + 3, id, 6);
    w = putAd(out + n, cap - n, kAdServiceData16, sd, sizeof(sd));
    if (!w) return 0;
    n += w;

    return n;
}

// ---- Google Fast Pair -------------------------------------------------------

size_t buildFastPair(uint8_t* out, size_t cap, const uint8_t modelId[3]) {
    if (out == nullptr || modelId == nullptr) return 0;

    size_t n = 0;
    const uint8_t flags = kFlagsLeOnly;

    size_t w = putAd(out + n, cap - n, kAdFlags, &flags, 1);
    if (!w) return 0;
    n += w;

    uint8_t uuid[2];
    putLe16(uuid, kServiceFastPair);
    w = putAd(out + n, cap - n, kAdService16All, uuid, sizeof(uuid));
    if (!w) return 0;
    n += w;

    // The discoverable form: service data is the UUID followed by the
    // three-byte model identifier and nothing else. That is the shape the
    // phone looks up, and looking it up is what raises the dialog.
    uint8_t sd[5];
    putLe16(sd, kServiceFastPair);
    std::memcpy(sd + 2, modelId, 3);
    w = putAd(out + n, cap - n, kAdServiceData16, sd, sizeof(sd));
    if (!w) return 0;
    n += w;

    return n;
}

// ---- Microsoft Swift Pair ---------------------------------------------------

size_t buildSwiftPair(uint8_t* out, size_t cap, const char* displayName) {
    if (out == nullptr) return 0;

    size_t n = 0;
    const uint8_t flags = kFlagsLeOnly;

    size_t w = putAd(out + n, cap - n, kAdFlags, &flags, 1);
    if (!w) return 0;
    n += w;

    //   FF 06 00 03 00 80 <display name>
    //
    // 0x03 is Microsoft's beacon identifier, 0x00 the sub-scenario "pairing
    // over LE only", and 0x80 a reserved RSSI byte. The display name that
    // follows is what Windows shows the person, which is the one place in this
    // file where a test label is worth keeping: somebody who is interrupted
    // should be able to read what interrupted them.
    uint8_t payload[2 + 3 + 24];
    size_t i = 0;
    putLe16(payload + i, kCompanyMicrosoft); i += 2;
    payload[i++] = 0x03;
    payload[i++] = 0x00;
    payload[i++] = 0x80;

    // The name is clamped against what is LEFT IN THE PACKET, not against this
    // local buffer. Clamping against the buffer looked right and was not: with
    // the flags structure already written there were 28 bytes left, a 24-byte
    // name made a 31-byte structure, putAd refused it, and the builder returned
    // zero. A long display name therefore produced NOTHING on the air while
    // the screen reported an armed emulation -- caught by the test named after
    // it, which is the only reason it is not still true.
    size_t room = sizeof(payload) - i;
    const size_t left = cap - n;
    if (left < i + 2) return 0;
    const size_t roomInPacket = left - 2 - i;   // minus this structure's header
    if (roomInPacket < room) room = roomInPacket;

    size_t nameLen = displayName ? std::strlen(displayName) : 0;
    if (nameLen > room) nameLen = room;
    if (nameLen) std::memcpy(payload + i, displayName, nameLen);
    i += nameLen;

    w = putAd(out + n, cap - n, kAdManufacturer, payload, i);
    if (!w) return 0;
    n += w;

    return n;
}

// ---- Flipper Zero -----------------------------------------------------------

size_t buildFlipper(uint8_t* out, size_t cap, const char* name, uint8_t colour) {
    if (out == nullptr) return 0;

    size_t n = 0;
    const uint8_t flags = kFlagsLeOnly;

    size_t w = putAd(out + n, cap - n, kAdFlags, &flags, 1);
    if (!w) return 0;
    n += w;

    // The NAME is the tell here, and it is a weaker one than every other
    // emulation in this file: anything may advertise any name. The screen says
    // so, because a detector that keys on this string is detecting a string.
    //
    // AND THERE IS DELIBERATELY NO MANUFACTURER DATA.
    //
    // A company identifier was written here first, taken from memory rather
    // than from the registry. That is exactly the mistake that put "Arlo"
    // against an Espressif OUI in somebody else's firmware: a number attributed
    // to a real company, believed by everyone who read the capture afterwards.
    // An identifier that cannot be checked does not go on the air, so this
    // emulation carries the name and the transmit power and nothing else --
    // which is also the honest shape, since the name is the whole tell.
    char buf[21];
    const char* src = (name && name[0]) ? name : "Flipper Orthrus";
    size_t nameLen = std::strlen(src);
    if (nameLen > sizeof(buf) - 1) nameLen = sizeof(buf) - 1;
    std::memcpy(buf, src, nameLen);
    buf[nameLen] = '\0';

    w = putAd(out + n, cap - n, kAdNameComplete,
              reinterpret_cast<const uint8_t*>(buf), nameLen);
    if (!w) return 0;
    n += w;

    // Transmit power, which a real one advertises and which gives a detector
    // something to range with. `colour` is the hardware variant a Flipper
    // reports over its own GATT service rather than in its advertisement, so
    // it is folded into the power byte's low bits rather than invented into a
    // manufacturer structure that does not exist.
    const uint8_t txPower = static_cast<uint8_t>(0xF4 + (colour % 3));  // -12..-10 dBm
    w = putAd(out + n, cap - n, kAdTxPower, &txPower, 1);
    if (!w) return 0;
    n += w;

    return n;
}

// ---- the set ----------------------------------------------------------------

const char* emulationName(Emulation e) {
    switch (e) {
        case Emulation::FindMy:    return "Find My";
        case Emulation::Tile:      return "Tile";
        case Emulation::SmartTag:  return "SmartTag";
        case Emulation::FastPair:  return "Fast Pair";
        case Emulation::SwiftPair: return "Swift Pair";
        case Emulation::Flipper:   return "Flipper";
        case Emulation::Count:     break;
    }
    return "?";
}

bool emulationPopsDialog(Emulation e) {
    return e == Emulation::FastPair || e == Emulation::SwiftPair;
}

size_t buildEmulation(Emulation e, uint8_t* out, size_t cap, uint32_t salt) {
    switch (e) {
        case Emulation::FindMy: {
            uint8_t key[kFindMyKeyLen];
            deriveIdentity(key, sizeof(key), salt);
            return buildFindMy(out, cap, key, 0x10);
        }
        case Emulation::Tile: {
            uint8_t id[6];
            deriveIdentity(id, sizeof(id), salt);
            return buildTile(out, cap, id);
        }
        case Emulation::SmartTag: {
            uint8_t id[6];
            deriveIdentity(id, sizeof(id), salt);
            return buildSmartTag(out, cap, id);
        }
        case Emulation::FastPair: {
            uint8_t model[3];
            deriveIdentity(model, sizeof(model), salt);
            return buildFastPair(out, cap, model);
        }
        case Emulation::SwiftPair:
            return buildSwiftPair(out, cap, "ORTHRUS-TEST");
        case Emulation::Flipper: {
            uint8_t c[1];
            deriveIdentity(c, 1, salt);
            return buildFlipper(out, cap, "Flipper Orthrus",
                                static_cast<uint8_t>(c[0] % 3));
        }
        case Emulation::Count:
            break;
    }
    return 0;
}

Emulation swarmStep(uint32_t n) {
    // The four observational emulations, and only those. A volume test that
    // raises forty pairing dialogs in a shared building is not a test, so the
    // rotation cannot reach Fast Pair or Swift Pair even if a caller asks it
    // to -- the table is the guard, not a comment.
    static constexpr Emulation kRotation[] = {
        Emulation::FindMy,
        Emulation::Tile,
        Emulation::SmartTag,
        Emulation::Flipper,
    };
    constexpr uint32_t kCount = sizeof(kRotation) / sizeof(kRotation[0]);
    return kRotation[n % kCount];
}

}  // namespace orthrus::ble
