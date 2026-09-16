#include "sha256.h"

#include <cstring>

namespace orthrus::crypto {
namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t bigSigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t bigSigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t smallSigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t smallSigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

}  // namespace

void Sha256::reset() {
    state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f; state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
    bitCount_  = 0;
    bufferLen_ = 0;
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const uint8_t block[kSha256BlockLen]) {
    uint32_t w[64];

    // Big-endian load, done byte by byte so the code is correct regardless of
    // host endianness or alignment.
    for (int i = 0; i < 16; i++) {
        w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; i++) {
        w[i] = smallSigma1(w[i - 2]) + w[i - 7] + smallSigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (int i = 0; i < 64; i++) {
        const uint32_t t1 = h + bigSigma1(e) + ch(e, f, g) + kK[i] + w[i];
        const uint32_t t2 = bigSigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256::update(const void* data, size_t len) {
    if (data == nullptr || len == 0) return;
    const uint8_t* p = static_cast<const uint8_t*>(data);
    bitCount_ += static_cast<uint64_t>(len) * 8u;

    // Top up a partial block first.
    if (bufferLen_ > 0) {
        const size_t need = kSha256BlockLen - bufferLen_;
        const size_t take = (len < need) ? len : need;
        std::memcpy(buffer_ + bufferLen_, p, take);
        bufferLen_ += take;
        p += take;
        len -= take;
        if (bufferLen_ == kSha256BlockLen) {
            compress(buffer_);
            bufferLen_ = 0;
        }
    }

    while (len >= kSha256BlockLen) {
        compress(p);
        p += kSha256BlockLen;
        len -= kSha256BlockLen;
    }

    if (len > 0) {
        std::memcpy(buffer_, p, len);
        bufferLen_ = len;
    }
}

void Sha256::finish(uint8_t out[kSha256DigestLen]) {
    const uint64_t bits = bitCount_;

    // 0x80, then zeroes, then the 64-bit big-endian length.
    const uint8_t pad = 0x80;
    update(&pad, 1);
    bitCount_ = bits;  // padding must not count toward the length

    const uint8_t zero = 0x00;
    while (bufferLen_ != 56) {
        update(&zero, 1);
        bitCount_ = bits;
    }

    uint8_t lenBytes[8];
    for (int i = 0; i < 8; i++) {
        lenBytes[i] = static_cast<uint8_t>((bits >> (56 - i * 8)) & 0xFF);
    }
    update(lenBytes, 8);

    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = static_cast<uint8_t>((state_[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((state_[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>((state_[i]) & 0xFF);
    }
}

void sha256(const void* data, size_t len, uint8_t out[kSha256DigestLen]) {
    Sha256 h;
    h.update(data, len);
    h.finish(out);
}

void toHex(const uint8_t digest[kSha256DigestLen], char out[65]) {
    static const char* kHex = "0123456789abcdef";
    for (size_t i = 0; i < kSha256DigestLen; i++) {
        out[i * 2 + 0] = kHex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[digest[i] & 0x0F];
    }
    out[64] = '\0';
}

bool equalConstantTime(const uint8_t a[kSha256DigestLen],
                       const uint8_t b[kSha256DigestLen]) {
    uint8_t diff = 0;
    for (size_t i = 0; i < kSha256DigestLen; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

}  // namespace orthrus::crypto
