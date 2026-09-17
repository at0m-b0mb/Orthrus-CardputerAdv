// What we have on each access point, and whether it is enough.
//
// The table is keyed on the PAIR (access point, station), not on the access
// point alone. A busy AP runs a separate four-way handshake with every client
// that joins, each with its own nonces and its own replay counters, and mixing
// two of them together produces a hash line that is internally inconsistent and
// will never crack. Keying on the pair is not an optimisation; it is the
// difference between a file that works and a file that looks like it should.
//
// THE HONEST LABEL
//
// Every target reports what it has -- PMKID, individual messages, a usable pair
// -- rather than a green tick. "Crackable" here means exactly one thing: the
// bytes needed for an offline guessing attack are present. It says nothing
// about whether the passphrase will fall. A twenty-character random passphrase
// produces exactly the same capture as "password1" and this device cannot tell
// them apart, so it does not pretend to.
//
// MEMORY
//
// A Table is about 7 KB. That is far too big for the Arduino loop task's 8 KB
// stack: declare one as a local and the device reboots the moment it is
// touched. Every instance in this firmware is static, and this is the same trap
// the LoRaWAN census fell into once already.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

#include "dot11/eapol.h"
#include "dot11/frame.h"

namespace orthrus::dot11 {

// Enough for the 802.1X payload of any M2 seen in practice: header plus the
// 95 byte descriptor plus the client's RSN element is around 121 bytes, and
// 256 leaves room for the larger key data some supplicants send.
inline constexpr size_t kEapolMax = 256;

// How much of a handshake we hold, worst to best. The order is meaningful and
// is used for sorting, so new values go in the right place rather than at the
// end.
enum class Quality : uint8_t {
    Nothing = 0,   // seen, nothing captured
    Fragment,      // EAPOL frames, but not a set that pairs up
    Pmkid,         // a PMKID: attackable with no client involved at all
    Handshake,     // a usable message pair
    Both,          // a usable pair AND a PMKID
};

// The MESSAGEPAIR byte in a hashcat 22000 line. Only the pairings this device
// can actually produce are listed; the rest are deliberately absent rather than
// guessed at.
inline constexpr uint8_t kPairM1M2 = 0x00;  // anonce from M1, MIC+EAPOL from M2
inline constexpr uint8_t kPairM2M3 = 0x02;  // anonce from M3, MIC+EAPOL from M2

// Set when the replay counters of the two messages do not line up. hashcat
// still accepts the line; the flag tells it (and the operator) that the pairing
// is by association in time rather than by protocol.
inline constexpr uint8_t kPairNotReplayChecked = 0x80;

struct Target {
    uint8_t bssid[kMacLen] = {0};
    uint8_t sta[kMacLen]   = {0};
    char    ssid[kSsidBuf] = {0};
    uint8_t channel = 0;
    int8_t  rssi    = 0;

    // Where the channel number came from. The beacon's DS Parameter Set is the
    // access point's actual operating channel; the channel we received a frame
    // on is only where our own radio happened to be pointing, and 2.4 GHz
    // channels overlap enough that a strong AP five channels away is heard
    // anyway. Letting the reception channel overwrite the beacon's sends an
    // operator to lock onto the wrong channel and wait there for nothing.
    bool channelFromBeacon = false;

    bool haveM1 = false, haveM2 = false, haveM3 = false, haveM4 = false;

    // The access point's nonce. M1 and M3 carry the same one -- the AP picks it
    // once per handshake -- so either will do, but which one we got decides
    // which message pair the hash line can claim.
    uint8_t anonce[kNonceLen] = {0};
    bool    haveAnonce        = false;
    bool    anonceFromM1      = false;

    uint64_t rcM1 = 0, rcM2 = 0, rcM3 = 0;

    // The MIC-bearing message, kept verbatim with its MIC field zeroed: that is
    // what both endpoints hashed, and what a cracker has to reproduce.
    uint8_t  mic[kMicLen]    = {0};
    uint8_t  eapol[kEapolMax] = {0};
    uint16_t eapolLen        = 0;
    bool     eapolOversize   = false;  // seen, but longer than we can store

    uint8_t pmkid[kPmkidLen] = {0};
    bool    havePmkid        = false;

    uint32_t eapolFrames = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs  = 0;

    bool    named() const { return ssid[0] != '\0'; }
    Quality quality() const;

    // Fills `out` with the MESSAGEPAIR byte for a hash line, or returns false
    // when no usable pairing exists yet.
    bool messagePair(uint8_t& out) const;
};

class Table {
public:
    static constexpr uint8_t kMaxTargets = 16;
    static constexpr uint8_t kMaxNames   = 24;

    void clear();

    // Records an access point's name and channel from a beacon or probe
    // response. Kept in its own small cache as well as pushed onto any existing
    // targets, so a handshake heard BEFORE the beacon still gets named when the
    // beacon arrives -- and one heard after is named immediately.
    void noteBeacon(const uint8_t bssid[kMacLen], const char* ssid, uint8_t channel,
                    int8_t rssi);

    // Folds one parsed EAPOL-Key frame into the table. `payload` is the raw
    // 802.1X payload, needed verbatim for the hash line.
    //
    // Returns the target it landed on, or nullptr when the frame was not usable
    // or the table is full.
    Target* ingest(const uint8_t bssid[kMacLen], const uint8_t sta[kMacLen],
                   const KeyFrame& kf, const uint8_t* payload, size_t payloadLen,
                   uint8_t channel, int8_t rssi, uint32_t nowMs);

    uint8_t       count() const { return count_; }
    const Target& at(uint8_t i) const { return targets_[i]; }
    Target&       at(uint8_t i) { return targets_[i]; }

    // How many targets hold something worth exporting.
    uint8_t exportable() const;

    bool full() const { return count_ >= kMaxTargets; }

    // Targets dropped because the table was full. Reported rather than hidden:
    // a silent cap looks exactly like a quiet radio.
    uint32_t dropped() const { return dropped_; }

private:
    struct Name {
        uint8_t bssid[kMacLen] = {0};
        char    ssid[kSsidBuf] = {0};
        uint8_t channel        = 0;
        bool    used           = false;
    };

    int  find(const uint8_t bssid[kMacLen], const uint8_t sta[kMacLen]) const;
    const Name* lookupName(const uint8_t bssid[kMacLen]) const;

    // Keeps the MIC-bearing message verbatim, with the MIC field zeroed.
    static void storeMicFrame(Target& t, const KeyFrame& kf, const uint8_t* payload,
                              size_t payloadLen);

    Target  targets_[kMaxTargets];
    uint8_t count_ = 0;

    Name    names_[kMaxNames];
    uint8_t nameCount_ = 0;
    uint8_t nameNext_  = 0;  // round robin once the cache is full

    uint32_t dropped_ = 0;
};

const char* qualityName(Quality q);

// One line of plain English for the operator, explaining what this quality
// means they can and cannot do.
const char* qualityDetail(Quality q);

}  // namespace orthrus::dot11
