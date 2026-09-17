// Published default keys for Mifare Classic.
//
// WHAT THIS IS, AND WHAT IT IS NOT
//
// This is a list of keys that are printed in vendor documentation, shipped in
// open-source tooling, and written on the first page of every tutorial on the
// subject. Trying them proves whether a badge was ever configured at all. It is
// the single most useful thing an authorized tester can establish about a
// Mifare Classic installation, and it needs no attack of any kind.
//
// It is NOT a key-recovery attack. Orthrus does not implement the nested or
// darkside attacks against Crypto1, and does not need to: if a site left the
// factory key in place, that is the finding, and if it did not, the correct
// answer is "we could not open it" rather than a longer grind.
//
// Every key below is public. Provenance is noted per entry so a reader can
// check rather than take it on trust.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::credential {

inline constexpr size_t kKeyLen = 6;

struct DefaultKey {
    uint8_t     key[kKeyLen];
    const char* origin;  // where this key comes from, so the list is auditable
};

const DefaultKey* defaultKeys();
size_t            defaultKeyCount();

}  // namespace orthrus::credential
