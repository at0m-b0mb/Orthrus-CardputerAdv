// Export formats: hashcat 22000 lines, and pcap headers.
//
// A capture that only exists on the device is not a deliverable. These are the
// two formats the rest of the world already reads -- hashcat mode 22000 for the
// offline attack, and pcap for anyone who wants to look at the frames
// themselves in Wireshark or feed them through hcxtools.
//
// Both formats are byte-exact and externally defined, which is precisely why
// they are here in the pure layer with tests around them: a single wrong
// separator produces a file that is silently rejected at the other end, and the
// operator finds out hours later on somebody else's machine.
//
// Pure and host-testable. No Arduino, no radio, no allocation, no file I/O.

#pragma once

#include <cstddef>
#include <cstdint>

#include "dot11/capture.h"

namespace orthrus::dot11 {

// Longest possible hash line: WPA*02* + MIC(32) + two MACs(24) + ESSID(64) +
// ANONCE(64) + EAPOL(512) + pair(2) + separators, with room to spare.
inline constexpr size_t kHashLineMax = 768;

// Lower-case hex, no separators. Returns characters written, excluding the NUL.
// Writes nothing and returns 0 if the output cannot hold it.
size_t toHex(const uint8_t* data, size_t len, char* out, size_t cap);

// One `WPA*01*` PMKID line, without a trailing newline.
//
// Returns 0 when the target has no PMKID, or when the buffer is too small --
// never a partial line, because half a hash line in a file is worse than none.
size_t writePmkidLine(const Target& t, char* out, size_t cap);

// One `WPA*02*` EAPOL line, without a trailing newline. Returns 0 when there is
// no usable message pair.
size_t writeEapolLine(const Target& t, char* out, size_t cap);

// ---- pcap -------------------------------------------------------------------

inline constexpr uint32_t kPcapMagic           = 0xA1B2C3D4u;
inline constexpr uint32_t kLinkTypeIeee80211   = 105;
inline constexpr size_t   kPcapGlobalHeaderLen = 24;
inline constexpr size_t   kPcapRecordHeaderLen = 16;

// Writes the 24 byte file header. Little-endian, which is what the magic
// declares and what every tool on the operator's laptop expects.
size_t writePcapGlobalHeader(uint8_t* out, size_t cap, uint32_t snaplen);

// Writes one 16 byte per-packet header.
//
// `origLen` is the length the frame had on the air; `inclLen` is how much of it
// is actually stored. They differ when a frame is longer than the snap length,
// and getting that backwards makes the file unreadable past the first truncated
// packet.
size_t writePcapRecordHeader(uint8_t* out, size_t cap, uint32_t tsSec,
                             uint32_t tsUsec, uint32_t inclLen, uint32_t origLen);

}  // namespace orthrus::dot11
