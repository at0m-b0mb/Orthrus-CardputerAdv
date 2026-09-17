// IEEE 802.11 frame headers, as a monitor-mode radio hands them over.
//
// This is the layer everything else in Harvest stands on, so it is deliberately
// paranoid. Every frame parsed here arrived over the air from somebody we have
// never met, with a length field they chose, and the parser runs inside the
// Wi-Fi driver's own callback. A missing bounds check is not a crash in a tool,
// it is a crash in the radio stack.
//
// Two details cost more time than the rest of the file put together, so they
// are written down rather than rediscovered:
//
//   1. The header is not a fixed 24 bytes. A QoS data frame carries two extra
//      bytes of QoS control, a four-address (WDS) frame carries six more, and
//      an ordered QoS frame carries four more of HT control. Get this wrong and
//      the EAPOL payload is read from the wrong offset -- which does not throw
//      an error, it just silently yields nothing, forever.
//
//   2. Which address is the access point depends on ToDS/FromDS, not on
//      position. Assuming addr1 is always the BSSID gets uplink frames right
//      and downlink frames exactly backwards.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::dot11 {

inline constexpr size_t kMacLen  = 6;
inline constexpr size_t kSsidMax = 32;
inline constexpr size_t kSsidBuf = kSsidMax + 1;

enum class FrameType : uint8_t {
    Management = 0,
    Control    = 1,
    Data       = 2,
    Extension  = 3,
};

// The management subtypes we actually act on. Others are parsed but ignored.
inline constexpr uint8_t kSubtypeAssocReq    = 0x00;
inline constexpr uint8_t kSubtypeAssocResp   = 0x01;
inline constexpr uint8_t kSubtypeProbeReq    = 0x04;
inline constexpr uint8_t kSubtypeProbeResp   = 0x05;
inline constexpr uint8_t kSubtypeBeacon      = 0x08;
inline constexpr uint8_t kSubtypeAuth        = 0x0B;
inline constexpr uint8_t kSubtypeDeauth      = 0x0C;

// Data subtypes: bit 3 marks the QoS variants.
inline constexpr uint8_t kDataQosBit = 0x08;

struct FrameInfo {
    FrameType type    = FrameType::Management;
    uint8_t   subtype = 0;
    bool      toDs    = false;
    bool      fromDs  = false;
    bool      protectedFrame = false;
    bool      ordered = false;

    uint8_t addr1[kMacLen] = {0};
    uint8_t addr2[kMacLen] = {0};
    uint8_t addr3[kMacLen] = {0};

    // Bytes of 802.11 header, including the QoS and HT control fields when
    // present. The frame body starts here.
    uint16_t headerLen = 0;
};

// Parses the MAC header. Returns false if the buffer is too short for the
// header this frame claims to have.
bool parseHeader(const uint8_t* frame, size_t len, FrameInfo& out);

// Works out which endpoint is the access point and which is the station.
//
// Returns false for a four-address (WDS/mesh) frame: there are two APs in that
// case and picking one would be a guess dressed up as a fact.
bool resolveEndpoints(const FrameInfo& fi, uint8_t bssid[kMacLen],
                      uint8_t sta[kMacLen]);

// ---- beacons and probe responses -------------------------------------------

// What the RSN information element says about a network.
//
// This is a much better source than the scan API's single "encryption type"
// number: it carries the actual cipher and authentication suites, and the
// capability bits that decide whether management frames can be forged.
struct RsnInfo {
    bool present = false;

    // Protected Management Frames, 802.11w. THE field that decides whether a
    // deauthentication can disconnect anyone on this network.
    //
    //   required -> management frames must be protected; forged deauths are
    //               ignored, and a deauth test proves the protection works
    //   capable  -> supported, negotiated per client; some clients protected,
    //               others not
    //   neither  -> every client can be disconnected by anyone in range
    bool pmfCapable  = false;
    bool pmfRequired = false;

    // Authentication suites actually advertised.
    bool akmPsk        = false;  // 00-0F-AC:2  pre-shared key
    bool akmPskSha256  = false;  // 00-0F-AC:6
    bool akmSae        = false;  // 00-0F-AC:8  WPA3 personal
    bool akmFtSae      = false;  // 00-0F-AC:9
    bool akmEnterprise = false;  // 00-0F-AC:1 / :5 / :3  802.1X
    bool akmOwe        = false;  // 00-0F-AC:18 opportunistic wireless encryption

    // Pairwise ciphers.
    bool cipherTkip = false;  // 00-0F-AC:2  deprecated, broken
    bool cipherCcmp = false;  // 00-0F-AC:4
    bool cipherGcmp = false;  // 00-0F-AC:8 / :9

    bool malformed = false;   // a length field inside the element did not add up
};

struct BeaconInfo {
    char     ssid[kSsidBuf] = {0};
    bool     ssidPresent    = false;  // the element existed
    bool     ssidHidden     = false;  // it existed but was empty or all NULs
    uint8_t  channel        = 0;      // from the DS Parameter Set, 0 if absent
    bool     hasRsn         = false;  // RSN information element (WPA2/WPA3)
    bool     hasWpa         = false;  // the older vendor-specific WPA element
    bool     hasWps         = false;  // Wi-Fi Protected Setup is advertised
    bool     truncated      = false;  // an element ran past the end of the frame
    RsnInfo  rsn;
};

// Parses the body of an RSN information element -- that is, the bytes AFTER
// the element id and length. Exposed on its own because association frames
// carry the same structure.
bool parseRsn(const uint8_t* data, size_t len, RsnInfo& out);

// Parses the tagged parameters of a beacon or probe response body. `body` must
// point at the start of the fixed parameters (timestamp), i.e. frame +
// headerLen.
bool parseBeacon(const uint8_t* body, size_t len, BeaconInfo& out);

// ---- EAPOL -----------------------------------------------------------------

// Finds the 802.1X payload inside a data frame, over the LLC/SNAP header.
//
// Returns false unless the frame really is an unencrypted EtherType 0x888E
// carrier. A protected frame cannot hold a readable EAPOL-Key, and treating one
// as if it could would feed ciphertext to the key parser.
bool eapolPayload(const uint8_t* frame, size_t len, const FrameInfo& fi,
                  const uint8_t** payload, size_t* payloadLen);

// Formats a MAC as aabbccddeeff (lower case, no separators) -- the shape the
// hashcat 22000 line wants. `out` needs 13 bytes.
void formatMacBare(const uint8_t mac[kMacLen], char out[13]);

// Formats a MAC as aa:bb:cc:dd:ee:ff for the screen. `out` needs 18 bytes.
void formatMacColons(const uint8_t mac[kMacLen], char out[18]);

bool macEqual(const uint8_t a[kMacLen], const uint8_t b[kMacLen]);
bool macIsZero(const uint8_t a[kMacLen]);

// Broadcast, multicast, or the all-zero address: never a real station.
bool macIsGroup(const uint8_t a[kMacLen]);

}  // namespace orthrus::dot11
