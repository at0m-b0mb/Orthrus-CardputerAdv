// SHA-256, FIPS 180-4.
//
// Written out rather than pulled from mbedtls because lib/core must build on
// the host with no ESP-IDF in sight -- that is the whole point of lib/core. It
// is a few hundred bytes of well-understood arithmetic, and it is checked
// against the NIST vectors in the test suite, including the million-character
// one.
//
// This is used for evidence integrity, not for secrecy. Nothing here is a
// substitute for a signature: a hash chain proves a log has not been edited
// since it was written, it does not prove who wrote it.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::crypto {

inline constexpr size_t kSha256DigestLen = 32;
inline constexpr size_t kSha256BlockLen  = 64;

class Sha256 {
public:
    Sha256() { reset(); }

    void reset();
    void update(const void* data, size_t len);

    // Writes kSha256DigestLen bytes. The object must be reset before reuse.
    void finish(uint8_t out[kSha256DigestLen]);

private:
    void compress(const uint8_t block[kSha256BlockLen]);

    uint32_t state_[8];
    uint64_t bitCount_;
    uint8_t  buffer_[kSha256BlockLen];
    size_t   bufferLen_;
};

// One-shot convenience.
void sha256(const void* data, size_t len, uint8_t out[kSha256DigestLen]);

// Lowercase hex, writes 64 characters plus a terminator. `out` must hold 65.
void toHex(const uint8_t digest[kSha256DigestLen], char out[65]);

// Constant-time comparison.
//
// Evidence verification compares a stored digest against a recomputed one. A
// byte-by-byte early-out leaks, through timing, how much of a forged digest was
// correct -- which is exactly the feedback an attacker needs to grind one out a
// byte at a time.
bool equalConstantTime(const uint8_t a[kSha256DigestLen],
                       const uint8_t b[kSha256DigestLen]);

}  // namespace orthrus::crypto
