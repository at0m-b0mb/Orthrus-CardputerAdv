// Bluetooth advertisements built by hand, to BE a named product.
//
// WHY THESE CARRY THE VENDOR'S OWN IDENTIFIERS
//
// Everything else this device puts on the air is labelled as a test. These are
// not, and the exception is the whole point.
//
// A tracker detector classifies by manufacturer company identifier or service
// UUID -- it has to, because a name is a string somebody typed and half the
// trackers in the world are called "iPhone". So a detector keying on Apple's
// 0x004C will CORRECTLY ignore an advertisement built from the Bluetooth SIG's
// reserved test identifier 0xFFFF. A test built that way proves nothing about
// the detector: it proves the detector does not react to a number nothing
// real ever sends.
//
// Proving a tracker detector recognises a tracker means putting a tracker's
// own bytes on the air. That is what these builders do, and nothing here
// pretends otherwise.
//
// THE TWO THAT ARE DIFFERENT
//
// Find My, Tile, SmartTag and Flipper are observational: a phone in range
// relays or ignores them and shows its owner nothing at all. Fast Pair and
// Swift Pair are pairing solicitations, and they put a dialog in front of
// whoever is holding the phone. That difference is carried in
// attack::Spec::popsDialog, and the arming screen leads with it, because
// "nobody notices" and "a stranger's phone interrupts them" are not the same
// permission.
//
// THE CEILING ON WHAT ANY OF THIS ESTABLISHES
//
// An emulation proves what a detector does with these bytes. It does not prove
// a real AirTag would behave identically -- a real one rotates its key on a
// schedule, answers Apple's crypto, and is attached to something. Nothing here
// claims to be a tracker. It claims to be a tracker's advertisement, which is
// a smaller and checkable thing.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

#include "ble/advert.h"

namespace orthrus::ble {

// A legacy advertising payload is 31 bytes. Not 31 bytes of data -- 31 bytes
// INCLUDING every AD structure's length and type byte, which is why Find My
// fills it exactly and has no room for a flags structure.
inline constexpr size_t kAdvertMax = 31;

// A Find My payload carries 22 bytes of an elliptic-curve public key. The real
// ones are a rotating key the finder network can resolve; these are not, and
// are not meant to be.
inline constexpr size_t kFindMyKeyLen = 22;

// Apple offline finding, as an AirTag emits it.
//
// Fills the payload exactly: one manufacturer-data structure of 31 bytes with
// no flags structure at all, which is what a non-connectable undirected
// tracker advertisement looks like on the air.
//
// `status` is the byte a real tag uses for its battery state and maintenance
// flags. Returns bytes written, or 0 if `cap` is too small.
size_t buildFindMy(uint8_t* out, size_t cap, const uint8_t key[kFindMyKeyLen],
                   uint8_t status);

// A Tile, by its service UUID and service data.
//
// Tile has shipped two UUIDs, 0xFEED and 0xFEEC. This emits the one asked for,
// because a detector that knows only the older one is a false negative worth
// being able to demonstrate.
size_t buildTile(uint8_t* out, size_t cap, const uint8_t id[6],
                 uint16_t serviceUuid = kServiceTile);

// A Samsung SmartTag, by Samsung's own service UUID.
//
// Deliberately NOT by company identifier alone. Every Galaxy phone, watch and
// pair of earbuds carries 0x0075, so an advertisement built from the company
// id would exercise a classifier that should not fire on it anyway.
size_t buildSmartTag(uint8_t* out, size_t cap, const uint8_t id[6]);

// A Google Fast Pair discoverable advertisement.
//
// RAISES A PAIRING DIALOG on Android phones in range. The three-byte model
// identifier is what the phone looks up to decide what picture to show.
size_t buildFastPair(uint8_t* out, size_t cap, const uint8_t modelId[3]);

// A Microsoft Swift Pair advertisement.
//
// RAISES A PAIRING NOTIFICATION on Windows machines in range. The display name
// is shown to the person, so it is the one place in this file where the test
// prefix is worth keeping: they should be able to see what interrupted them.
size_t buildSwiftPair(uint8_t* out, size_t cap, const char* displayName);

// A Flipper Zero.
//
// Identified by its advertised name rather than by a registry number, which is
// a weaker tell and is said so on the screen: anything may advertise any name.
// `colour` is the hardware variant byte a real one carries.
size_t buildFlipper(uint8_t* out, size_t cap, const char* name, uint8_t colour);

// ---- identities -------------------------------------------------------------

// A random-static Bluetooth address: the top two bits of the first byte set.
//
// Static rather than resolvable-private, because a swarm whose addresses
// rotate underneath it cannot be counted by anything watching, and the point of
// a swarm is to be countable.
//
// Deterministic in `salt`, so a run can be reproduced and the tests can assert
// it.
void randomStaticAddress(uint8_t out[kAddrLen], uint32_t salt);

// Fills `out` with `len` deterministic bytes, for a key, a Tile id or a model
// identifier. Deterministic for the same reason.
void deriveIdentity(uint8_t* out, size_t len, uint32_t salt);

// ---- the swarm --------------------------------------------------------------

enum class Emulation : uint8_t {
    FindMy = 0,
    Tile,
    SmartTag,
    FastPair,
    SwiftPair,
    Flipper,
    Count
};

const char* emulationName(Emulation e);

// True when this emulation puts a dialog in front of a person.
bool emulationPopsDialog(Emulation e);

// Builds whichever emulation `e` names, deriving its identity from `salt`.
size_t buildEmulation(Emulation e, uint8_t* out, size_t cap, uint32_t salt);

// Which emulation step `n` of a swarm should advertise.
//
// Skips the two that raise dialogs. A swarm is a volume test, and a volume test
// that interrupts forty strangers is not a test, it is a nuisance -- so the
// rotation cannot reach them even if a future caller forgets.
Emulation swarmStep(uint32_t n);

}  // namespace orthrus::ble
