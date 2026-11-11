// 802.11 frames built by hand, for the surfaces that transmit.
//
// WHY THESE ARE HERE AND NOT IN THE MODULES
//
// The 802.11w test used to carry its own deauthentication builder, 26 bytes
// written inline, and that was fine while there was one of them. There are now
// seven frame shapes across five surfaces, and a frame layout is exactly the
// kind of thing that is either byte-exact or silently useless: a wrong offset
// does not throw, it produces a frame every stack on the air quietly discards
// while the screen counts up and concludes "no effect seen" -- which reads
// identically to a properly protected network.
//
// So every builder lives here, pure, with a test that asserts its bytes
// against the standard's layout rather than against itself.
//
// WHAT IS DELIBERATELY NOT HERE
//
// No FCS. The radio appends the four-byte frame check sequence itself, and a
// builder that added one would send four bytes of garbage inside the body and
// have the real FCS computed over it. This cost real time in the firmware this
// came from, where frame LENGTHS were being reported including an FCS that the
// caller had not written -- so the lengths returned here are exactly the bytes
// to hand the radio.
//
// No transmission. Nothing in this file touches a radio, which is why it can
// be proven on a laptop.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

#include "dot11/frame.h"

namespace orthrus::dot11 {

// Every builder fits inside this. The largest is a beacon carrying an SSID, a
// rate set, a DS parameter set, an RSN element and a channel-switch element.
inline constexpr size_t kInjectMax = 192;

// Sequence numbers, which have to advance.
//
// esp_wifi_80211_tx is called with en_sys_seq=false, which means the MAC does
// NOT fill the sequence control field in. Leaving it at zero sends every frame
// with the same sequence number forever, and a receiving stack is entitled to
// treat the second one as a retransmission of the first and drop it -- so a
// burst of two hundred frames can land as one.
//
// Twelve bits, wrapping, exactly as the field is.
class Sequencer {
public:
    uint16_t next() {
        const uint16_t s = seq_;
        seq_ = static_cast<uint16_t>((seq_ + 1) & 0x0FFF);
        return s;
    }
    uint16_t peek() const { return seq_; }
    void reset() { seq_ = 0; }

private:
    uint16_t seq_ = 0;
};

// ---- disconnects ------------------------------------------------------------

// Reason 7, "class 3 frame received from nonassociated station", is what a real
// access point sends when it wants a client to start again. It is therefore the
// frame 802.11w exists to authenticate, which makes it the right one to test
// with. Reason 1 (unspecified) and 4 (inactivity) are offered too, because some
// stacks honour one and ignore another.
inline constexpr uint16_t kReasonUnspecified   = 1;
inline constexpr uint16_t kReasonInactivity    = 4;
inline constexpr uint16_t kReasonClass3NonAssoc = 7;

// One deauthentication frame.
//
// `src` is the address the frame claims to come from, and it is a separate
// argument rather than always the BSSID on purpose: a disconnect is only
// honoured in the direction it plausibly travels. Spoofing the ACCESS POINT at
// a client is one test; spoofing the CLIENT at the access point is a different
// one, and some equipment ignores the first while obeying the second. Sending
// both is what actually clears a cell.
//
// Returns the number of bytes written, or 0 if `cap` cannot hold the frame.
size_t buildDeauth(uint8_t* out, size_t cap, const uint8_t dest[kMacLen],
                   const uint8_t src[kMacLen], const uint8_t bssid[kMacLen],
                   uint16_t reason, Sequencer& seq);

// One disassociation frame. Same shape, different subtype: the distinction
// matters because a deauthentication says "you are not authenticated" and a
// disassociation says "you are no longer associated", and stacks differ in
// which they will accept from an unauthenticated source.
size_t buildDisassoc(uint8_t* out, size_t cap, const uint8_t dest[kMacLen],
                     const uint8_t src[kMacLen], const uint8_t bssid[kMacLen],
                     uint16_t reason, Sequencer& seq);

// ---- being an access point --------------------------------------------------

// What the beacon claims about its own security.
//
// This is not a cipher suite picker. It is three honest shapes: no encryption
// at all, WPA2 with CCMP and a pre-shared key, and WPA3 with SAE and management
// frames required. Twin beacon uses the mismatch deliberately -- a WPA2 network
// twinned as Open is the clearest possible test of whether a client checks.
enum class BeaconSecurity : uint8_t { Open = 0, Wpa2Psk, Wpa3Sae };

// A beacon frame.
//
// `ssid` may be empty, which produces a hidden-network beacon with a
// zero-length SSID element -- a real shape, and worth being able to emit.
size_t buildBeacon(uint8_t* out, size_t cap, const char* ssid,
                   const uint8_t bssid[kMacLen], uint8_t channel,
                   BeaconSecurity sec, Sequencer& seq);

// A beacon carrying a Channel Switch Announcement.
//
// `count` is how many beacon intervals until the switch; 0 means immediately.
// Mode 1 tells clients to stop transmitting until the switch happens, which is
// what makes this disruptive rather than merely rude: a client that obeys both
// fields goes quiet and then moves to a channel the access point is not on.
size_t buildCsaBeacon(uint8_t* out, size_t cap, const char* ssid,
                      const uint8_t bssid[kMacLen], uint8_t channel,
                      uint8_t newChannel, uint8_t count, BeaconSecurity sec,
                      Sequencer& seq);

// A probe response, addressed to the station that asked.
//
// This is the whole of Karma: a device that has ever joined "AirportFreeWiFi"
// keeps asking for it by name wherever it goes, and an answer from anybody at
// all is enough to make it try. The answer is a probe response carrying the
// name that was asked for.
size_t buildProbeResponse(uint8_t* out, size_t cap, const char* ssid,
                          const uint8_t bssid[kMacLen],
                          const uint8_t dest[kMacLen], uint8_t channel,
                          BeaconSecurity sec, Sequencer& seq);

// ---- knocking on the door ---------------------------------------------------

// An open-system authentication request, transaction 1.
//
// The first step of joining, and on its own the cheapest way to occupy a slot
// in an access point's association table.
size_t buildAuthRequest(uint8_t* out, size_t cap, const uint8_t bssid[kMacLen],
                        const uint8_t src[kMacLen], Sequencer& seq);

// An association request naming the network and asking for WPA2-PSK.
//
// Used for two different things. As a flood it is the step after
// authentication, which some access points handle gracefully and others do
// not. Singly, it is how a PMKID is solicited: an access point with a cached
// PMK answers an association with EAPOL message 1, and some of them put a
// PMKID in it, which is offline-attackable with no client ever involved.
//
// The RSN element asks for PSK with CCMP specifically, because an access point
// will not volunteer a PMKID to a request whose AKM it does not support.
size_t buildAssocRequest(uint8_t* out, size_t cap, const char* ssid,
                         const uint8_t bssid[kMacLen],
                         const uint8_t src[kMacLen], Sequencer& seq);

// ---- invented addresses -----------------------------------------------------

// A station address for a flood, or for an invented access point.
//
// The locally-administered bit is SET and the multicast bit is cleared, which
// means this address was never assigned to anybody. That is not a detail: an
// address generated at random across the whole space lands on real OUIs, so a
// flood would attribute hundreds of frames to a manufacturer who had nothing to
// do with it, and anyone reading the capture afterwards would believe it.
//
// Deterministic in `salt`, so the tests can assert it and a swarm can be
// reproduced.
void inventedAddress(uint8_t out[kMacLen], uint32_t salt);

// True when this address could never have been assigned by the registry --
// which is what the builders above guarantee about every address they invent.
bool addressIsInvented(const uint8_t addr[kMacLen]);

}  // namespace orthrus::dot11
