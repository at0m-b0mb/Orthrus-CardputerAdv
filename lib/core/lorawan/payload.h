// Is this FRMPayload actually encrypted?
//
// LoRaWAN encrypts FRMPayload with AES-128 in a CTR-like mode, so a correctly
// implemented device emits ciphertext that is statistically indistinguishable
// from random. Vendors get this wrong -- shipping plaintext JSON or CSV over
// the air -- and that is one of the highest-value findings a passive listener
// can produce, because it needs no keys to prove.
//
// The whole design problem here is refusing to cry wolf on short payloads. A
// 2-byte ciphertext has a ~14% chance of being two printable characters purely
// by luck, so claiming "plaintext" on it would be dishonest. Confidence is
// therefore derived from the actual false-positive probability, not picked.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::lorawan {

enum class PayloadSignal : uint8_t {
    NoEvidence = 0,     // too short, or looks like ciphertext
    PrintableText,      // every byte is printable ASCII
    StructuredText,     // JSON/CSV markers on top of printable
    LowDiversity,       // far too few distinct byte values for ciphertext
};

struct PayloadVerdict {
    PayloadSignal signal     = PayloadSignal::NoEvidence;
    uint8_t       confidence = 0;  // 0..97; never 100, we cannot see the keys
    const char*   reason     = "no evidence";

    bool looksPlaintext() const { return signal != PayloadSignal::NoEvidence; }
};

// Shortest payload we will ever call plaintext.
//
// A random byte is printable ASCII with probability 95/256 ~= 0.371. For n=8
// the chance that ciphertext is all-printable by luck is 0.371^8 ~= 3.6e-4,
// which is a defensible threshold. Below 8 it is not, so we stay silent.
inline constexpr uint8_t kMinPlaintextLen = 8;

PayloadVerdict inspectPayload(const uint8_t* payload, uint8_t len);

const char* payloadSignalName(PayloadSignal s);

}  // namespace orthrus::lorawan
