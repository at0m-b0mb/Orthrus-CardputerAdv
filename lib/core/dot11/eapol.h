// EAPOL-Key frames: the WPA/WPA2 four-way handshake, and the PMKID.
//
// WHAT A CAPTURE HERE ACTUALLY PROVES
//
// It proves the network's passphrase is now subject to an offline guessing
// attack: an attacker who holds these bytes can test candidate passphrases at
// whatever rate their own hardware allows, with nothing on the client's side
// able to see it happening or slow it down. That is the finding. It is NOT
// proof the passphrase is weak, and this device never claims to have recovered
// one -- it captures, names what it has, and hands you a file for a cracker
// that runs somewhere else.
//
// Absence proves nothing, as everywhere else in this product. Hearing no
// handshake means nobody joined while you were listening on that channel.
//
// WHY THE MESSAGE NUMBERS MATTER
//
// A handshake is only usable if the messages belong together. hashcat wants a
// specific pair, with the anonce from one and the MIC and the exact EAPOL bytes
// from the other, and it wants to know whether the replay counters lined up. A
// parser that collects "some EAPOL frames" and calls it a handshake produces
// files that never crack and never explain why.
//
// Pure and host-testable. No Arduino, no radio, no allocation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::dot11 {

inline constexpr size_t kNonceLen = 32;
inline constexpr size_t kMicLen   = 16;
inline constexpr size_t kPmkidLen = 16;

// 802.1X header (4) + key descriptor fixed fields (95).
inline constexpr size_t kEapolHeaderLen    = 4;
inline constexpr size_t kKeyDescriptorLen  = 95;
inline constexpr size_t kEapolKeyMinLen    = kEapolHeaderLen + kKeyDescriptorLen;

// Byte offset of the MIC field inside the 802.1X payload. Needed because
// hashcat wants the MIC-bearing frame with its MIC zeroed, which is what the
// access point and client themselves hashed.
inline constexpr size_t kMicOffset = 81;

inline constexpr uint8_t kEapolTypeKey = 3;

inline constexpr uint8_t kDescriptorRsn = 2;    // WPA2/WPA3
inline constexpr uint8_t kDescriptorWpa = 254;  // the original WPA

// key_info bits, as read from the big-endian field.
inline constexpr uint16_t kKeyInfoVersionMask = 0x0007;
inline constexpr uint16_t kKeyInfoPairwise    = 0x0008;
inline constexpr uint16_t kKeyInfoInstall     = 0x0040;
inline constexpr uint16_t kKeyInfoAck         = 0x0080;
inline constexpr uint16_t kKeyInfoMic         = 0x0100;
inline constexpr uint16_t kKeyInfoSecure      = 0x0200;
inline constexpr uint16_t kKeyInfoError       = 0x0400;
inline constexpr uint16_t kKeyInfoRequest     = 0x0800;
inline constexpr uint16_t kKeyInfoEncrypted   = 0x1000;

enum class Message : uint8_t { Unknown = 0, M1, M2, M3, M4 };

struct KeyFrame {
    Message  message        = Message::Unknown;
    uint8_t  descriptorType = 0;
    uint16_t keyInfo        = 0;
    uint8_t  keyVersion     = 0;
    uint64_t replayCounter  = 0;

    uint8_t  nonce[kNonceLen] = {0};
    bool     nonceIsZero      = true;

    uint8_t  mic[kMicLen] = {0};
    bool     micPresent   = false;

    uint16_t       keyDataLen = 0;
    const uint8_t* keyData    = nullptr;

    // Length of the whole 802.1X payload as the endpoints hashed it: header
    // plus descriptor plus key data. NOT the length of the buffer handed in,
    // which may carry padding the sender added below the 802.11 layer.
    uint16_t payloadLen = 0;

    bool pairwise() const { return (keyInfo & kKeyInfoPairwise) != 0; }
    bool ack() const      { return (keyInfo & kKeyInfoAck) != 0; }
    bool secure() const   { return (keyInfo & kKeyInfoSecure) != 0; }
    bool encrypted() const{ return (keyInfo & kKeyInfoEncrypted) != 0; }
};

// Parses an 802.1X payload. Returns false for anything that is not a
// well-formed pairwise EAPOL-Key frame.
bool parseKeyFrame(const uint8_t* payload, size_t len, KeyFrame& out);

// Pulls the PMKID out of an M1's key data, if the access point volunteered one.
//
// This is the whole of the "PMKID attack": some access points include a PMKID
// in the first message of the handshake, computed from the PMK, the two MAC
// addresses and a fixed label. It is offline-attackable on its own -- no client
// needs to be present, and no four-way handshake needs to complete.
//
// Returns false when there is no PMKID KDE, when the key data is encrypted, or
// when the PMKID is all zeroes (some access points emit a zero-filled KDE as a
// placeholder, and feeding that to a cracker wastes a run).
bool extractPmkid(const KeyFrame& kf, uint8_t out[kPmkidLen]);

const char* messageName(Message m);

}  // namespace orthrus::dot11
