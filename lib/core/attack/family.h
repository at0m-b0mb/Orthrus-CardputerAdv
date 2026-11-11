// The transmit families, and the gate every one of them goes through.
//
// Orthrus had exactly one surface that put energy on the air at an operator's
// command -- the 802.11w test -- and all of its doctrine lived inside that one
// module. Adding beacons, Karma, floods, a channel-switch and seven Bluetooth
// emulations one module at a time would have produced nine copies of that
// doctrine, which is nine places for it to drift. So the doctrine moved here,
// where it is pure, host-testable, and the same for every radio.
//
// WHAT A FAMILY IS
//
// One thing the device can put on the air against a target the operator chose
// by hand, with a hard ceiling on rate and duration that a plan may LOWER and
// never raise. Three facts travel with each one and all three are required:
//
//   name    what it is called on the screen
//   proves  what running it establishes -- the question for whoever reads the
//           report afterwards
//   effect  what it does to the people on that network, in their language and
//           not the protocol's -- the question for whoever has a finger on the
//           arming key
//
// `effect` exists because the arming screen used to show a frame count, a rate
// and a channel. All three are true and none of them say that everybody in the
// building is about to drop off the Wi-Fi. A family that cannot say what it
// does to the target has not been thought through, so the table has no row
// without one.
//
// THREE DEFECTS THIS FILE EXISTS TO MAKE IMPOSSIBLE
//
// These were all found on the author's own hardware in Basanos, which is the
// firmware this doctrine comes from. Each has a test in the suite named after
// it, because an invariant with no test is a comment.
//
//   1. The authorisation check sat inside the "does this family need a target"
//      branch -- so the families that need no target, which is every Bluetooth
//      one, were never checked against an authorisation at all. Here the check
//      is unconditional and runs FIRST.
//
//   2. "Whole cell" and "one named client" were two independent flags, and the
//      destination resolver preferred whole-cell. Naming a client therefore
//      left the radio broadcasting at everybody while every screen reported a
//      narrowed scope. Here the scope is DERIVED from one field, so the two
//      cannot disagree.
//
//   3. A run that was refused still reached the scoring path, which read an
//      uninitialised frame count. Here validate() either returns Ok with a
//      clamped plan or returns a reason, and frameBudget() of an invalid plan
//      is defined.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::attack {

inline constexpr size_t kMacLen  = 6;
inline constexpr size_t kSsidBuf = 33;

// ---- what the device can put on the air -------------------------------------

enum class Family : uint8_t {
    // Impersonating a network.
    Beacon = 0,      // bounded, prefixed, invented access points
    TwinBeacon,      // the target's own name and BSSID, security class wrong
    Karma,           // answer other people's probe requests

    // Taking credential material off the target.
    Pmkid,           // solicit EAPOL M1 and keep the PMKID it volunteers

    // Denying service to something real.
    Deauth,
    Disassoc,
    AuthFlood,       // fill the access point's association table
    AssocFlood,      // association requests from many invented identities
    ChannelSwitch,   // a forged CSA that moves clients off their channel

    // Emulating a specific Bluetooth product, with that vendor's own
    // identifiers. See ble/emulate.h for why the SIG test identifier will not
    // do.
    BleFindMy,
    BleTile,
    BleSmartTag,
    BleFastPair,     // puts a pairing dialog in front of a person
    BleSwiftPair,    // puts a pairing dialog in front of a person
    BleFlipper,
    BleSwarm,        // many identities at once, rotating through the above

    Count
};

enum class Radio : uint8_t { Wifi = 0, Ble };

// How much harm it does.
enum class Klass : uint8_t {
    Benign = 0,     // adds traffic, denies nothing, deceives nobody
    Active,         // visible on air and aimed at the target
    Disruptive,     // something real stops working for somebody
};

// What the operator came to do, which is not the same question.
//
// Klass says how dangerous a family is; Group says what it is FOR. With
// sixteen families a single list is a wall of names an operator has to read
// end to end, so the picker asks what they actually arrived with: am I
// knocking something over, taking a credential, pretending to be a network,
// or pretending to be a device.
enum class Group : uint8_t {
    Disrupt = 0,
    Capture,
    Impersonate,
    Emulate,
    Broadcast,
    Count
};

const char* groupName(Group g);
const char* groupBlurb(Group g);
const char* klassName(Klass k);
const char* radioName(Radio r);

struct Spec {
    const char* name;
    const char* proves;
    const char* effect;
    Klass       klass;
    Group       group;
    Radio       radio;

    // Requires an access point chosen by hand. Everything that aims at a real
    // network does; inventing beacons and emulating a luggage tag do not.
    bool needsTarget;

    // Meaningless without one specific station. Nothing in the table sets this
    // today -- deauth works against the whole cell too -- but the gate checks
    // it, so a future family cannot forget to.
    bool needsClient;

    // A pairing solicitation: a human holding a phone sees a dialog appear.
    // The first three emulations are observational -- a phone relays or
    // ignores them and shows its owner nothing -- and these two are not. The
    // arming screen leads with the difference.
    bool popsDialog;

    uint16_t defaultPps;
    uint16_t maxPps;      // a hard ceiling; a plan may lower it, never raise it
    uint16_t maxSeconds;  // the same, for one run
};

// nullptr for a value outside the table.
const Spec* spec(Family f);
const char* familyName(Family f);

// True for the families that live on the Bluetooth radio.
//
// Asked as a question rather than inferred from the enum's order, because that
// order has already changed once -- the emulations were inserted in the middle
// -- and a range check would have quietly started answering wrongly. The
// screen needs this to avoid printing a Wi-Fi channel beside an advertisement
// that has no channel.
bool isBle(Family f);

// ---- the authorisation ------------------------------------------------------

// Four hours. The ceiling is not about trust, it is about a device left in a
// bag: a continuous run checks the authorisation before every burst, so an
// expiry is what stops "until I stop it" becoming "until the battery dies".
inline constexpr uint32_t kMaxTtlMs = 4u * 60u * 60u * 1000u;

struct Authorization {
    bool     locked  = false;
    char     ssid[kSsidBuf]   = {0};
    uint8_t  bssid[kMacLen]   = {0};
    uint8_t  channel = 0;

    // One named station narrows every transmission to it. There is deliberately
    // no second flag for "the whole cell": scope is derived from this one, so
    // the screen and the radio cannot disagree about who is being hit.
    bool     haveClient = false;
    uint8_t  client[kMacLen] = {0};

    // Who said this was allowed, and under what reference. Free text, because
    // the device cannot verify either -- but an engagement log line that
    // carries them is a deliverable and one that does not is an anecdote.
    char     operatorName[24] = {0};
    char     reference[24]    = {0};

    uint32_t grantedMs = 0;
    uint32_t ttlMs     = 0;   // clamped to kMaxTtlMs by lock()

    bool     valid(uint32_t nowMs) const;
    uint32_t remainingMs(uint32_t nowMs) const;
};

// Locks an authorisation onto one access point. `ttlMs` is clamped down to
// kMaxTtlMs; it is never widened. Returns false, and locks nothing, for an
// all-zero or group BSSID -- a "target" that is really everybody.
bool lock(Authorization& a, const char* ssid, const uint8_t bssid[kMacLen],
          uint8_t channel, uint32_t nowMs, uint32_t ttlMs);

// Narrows an existing lock to one station, or widens it back to the cell with
// nullptr. Returns false when there is no lock to narrow, or when `client` is
// a group address, which would be a broadcast wearing a station's clothes.
bool lockClient(Authorization& a, const uint8_t client[kMacLen]);

void unlock(Authorization& a);

// Who a frame is addressed to, as one answer rather than two flags.
enum class Scope : uint8_t { WholeCell = 0, OneClient };

Scope scopeOf(const Authorization& a);
const char* scopeName(Scope s);

// Fills `out` with the address a frame should be sent to: the named station, or
// the broadcast address when the scope is the whole cell.
void destinationFor(const Authorization& a, uint8_t out[kMacLen]);

// ---- the plan ---------------------------------------------------------------

struct Plan {
    Family   family     = Family::Deauth;
    uint16_t pps        = 0;
    uint16_t seconds    = 0;   // 0 asks for a continuous run
    uint8_t  reasonCode = 7;   // 802.11 reason, for deauth and disassoc
    uint8_t  channel    = 0;   // 0 follows the target's channel

    bool     continuous     = false;
    bool     clampedPps     = false;  // set by validate when it lowered the rate
    bool     clampedSeconds = false;
};

// Fills a plan with the family's own defaults.
void planDefault(Plan& p, Family f);

enum class PlanError : uint8_t {
    Ok = 0,
    UnknownFamily,
    NotAuthorized,        // nothing is locked
    AuthorizationExpired,
    NoTarget,             // locked, but this family needs an access point
    NoClient,             // this family needs one named station
    ChannelRefused,       // outside the regulatory domain in force
};

const char* planErrorText(PlanError e);

// The gate every transmit path goes through.
//
// In this order, and the order is the point: the family must be known; an
// authorisation must be locked and unexpired -- checked for EVERY family,
// including the Bluetooth ones that need no target, because that is the check
// that was once skipped for exactly them; the target and client requirements
// must be met; the channel must be inside the domain in force. Then pps and
// seconds are clamped to the family's ceiling, and the plan records that they
// were.
//
// Returns Ok only when the run may proceed. `p` is modified in place, and on
// anything but Ok it is left alone rather than half-clamped.
PlanError validate(Plan& p, const Authorization& a, uint32_t nowMs);

// Total frames a validated plan will emit, or 0 when it is continuous and
// there is no total to give. The arming screen shows this, because "600 frames"
// is a number an operator can reason about and "20 pps for 30 s" is not.
//
// Defined for an unvalidated plan too: it returns 0 rather than reading a rate
// nobody clamped.
uint32_t frameBudget(const Plan& p);

// ---- the regulatory clamp ---------------------------------------------------

enum class Region : uint8_t { Fcc = 0, Etsi, Jp };

void   regionSet(Region r);
Region regionGet();
uint8_t regionMaxChannel();
const char* regionName(Region r);
bool   regionAllows(uint8_t channel);

// Maps a two-letter country code to the domain whose channel rules apply.
//
// An unknown code returns Fcc, which is the NARROWEST 2.4 GHz plan (1..11) and
// therefore the safe answer when the evidence is thin: guessing wide would
// authorise a transmission that guessing narrow merely refuses.
Region regionFromCountry(const char* cc);

// The narrowest domain that permits this channel. Fcc for a channel out of
// range, since refusing is safer than widening on a value that means nothing.
Region regionForChannel(uint8_t channel);

// Widens the clamp just enough to reach `channel`, and never narrows it.
//
// This exists because both alternatives were worse. Inferring the domain from
// the ROOM picks whatever most beacons claim, which is right for a survey and
// wrong for a target: a phone hotspot on channel 13 in a building full of
// channel 1..11 networks was simply unreachable, and the device reported a
// refusal rather than a result. The target is the authorisation boundary
// everywhere else here -- one network, chosen by hand -- so it is the right
// thing to take the channel plan from.
//
// Returns true when it changed the region, so the caller can say so. The
// operator is told every time: this can put the radio on a channel their own
// regulator does not permit, and that is their call to make knowingly.
bool regionWidenFor(uint8_t channel);

// ---- the test prefix --------------------------------------------------------

// Every SSID and Bluetooth name this device INVENTS carries this, so anybody
// else sniffing the room sees a test rig rather than an attack.
//
// The deliberate exception is TwinBeacon, which exists to carry the target's
// own name, and the product emulations, which exist to carry the vendor's own
// identifiers. Both are named exceptions with a reason, which is the only kind
// this file has.
#define ORTHRUS_TEST_PREFIX "ORTHRUS-"

bool labelOk(const char* label);

// True when this family is allowed to put a label on the air that does NOT
// carry the prefix, and therefore why.
bool familyMayImpersonate(Family f);

}  // namespace orthrus::attack
