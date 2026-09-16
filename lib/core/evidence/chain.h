// Tamper-evident evidence log.
//
// A capture that ends as an editable CSV is an anecdote. A capture whose
// records are linked by a hash chain, with the final digest read off the
// device's own screen and recorded independently, is something a client can
// rely on. That difference is most of what separates an audit instrument from
// a toy, and it is why this file exists.
//
// WHAT THIS PROVES, EXACTLY
//
// Each record commits to every record before it: head(n) = SHA256(head(n-1) ||
// record(n)). Change, insert, delete or reorder anything in the middle of the
// file and every digest from that point on stops matching. Verification is
// offline and needs no key.
//
// WHAT IT DOES NOT PROVE, AND WE SAY SO PLAINLY
//
// Anyone who can rewrite the whole file can also recompute the whole chain. A
// keyless chain cannot stop that, and claiming otherwise would be exactly the
// kind of unearned certainty this project refuses everywhere else. What closes
// the gap is recording the head digest somewhere the file cannot reach -- which
// is why the device shows it on screen at the end of a session, for the
// operator to photograph or write into their notes. Verified against a head
// recorded that way, the log is genuinely tamper-evident.
//
// It also proves nothing about WHO produced the log. That needs a signature,
// and a signing key on a device an attacker may be holding is not a signature
// anyone should trust.

#pragma once

#include <cstddef>
#include <cstdint>

#include "crypto/sha256.h"

namespace orthrus::evidence {

inline constexpr size_t kDetailLen = 96;

enum class RecordKind : uint8_t {
    SessionStart = 0,
    Device,
    Finding,
    Note,
    SessionEnd,
};

struct Record {
    uint32_t   seq    = 0;
    uint32_t   timeMs = 0;
    RecordKind kind   = RecordKind::Note;
    char       detail[kDetailLen] = {0};
};

// Canonical serialisation: seq(4 LE) | timeMs(4 LE) | kind(1) | detail(96).
//
// Fixed width and fixed order on purpose. A verifier must be able to rebuild
// exactly these bytes from a text export years later, so nothing here may
// depend on struct padding, host endianness, or how long the detail string
// happens to be.
inline constexpr size_t kSerialisedLen = 4 + 4 + 1 + kDetailLen;

void serialise(const Record& r, uint8_t out[kSerialisedLen]);

class Chain {
public:
    // Starts a session. The seed is hashed to form head(0); it should be
    // something session-specific (start time, operator, engagement reference)
    // so two sessions cannot produce the same chain.
    void begin(const void* seed, size_t seedLen);

    // Appends a record and writes the new head digest, which is what gets
    // stored alongside the record in the log file.
    void append(const Record& r, uint8_t outHead[crypto::kSha256DigestLen]);

    const uint8_t* head() const { return head_; }
    uint32_t       count() const { return count_; }

private:
    uint8_t  head_[crypto::kSha256DigestLen] = {0};
    uint32_t count_ = 0;
};

enum class VerifyStatus : uint8_t {
    Ok = 0,
    Empty,             // nothing to verify
    SequenceBroken,    // seq numbers are not consecutive from 0
    DigestMismatch,    // a record's stored digest does not match the recomputed one
    HeadMismatch,      // the chain is internally consistent but not the expected head
};

struct VerifyReport {
    VerifyStatus status     = VerifyStatus::Empty;
    uint32_t     recordsOk  = 0;   // how many verified before the first problem
    uint32_t     failedAt   = 0;   // sequence number of the first bad record

    bool ok() const { return status == VerifyStatus::Ok; }
};

// Replays a log and checks every digest.
//
// `expectedHead` is optional. Pass the digest the operator recorded off the
// device and a rewritten-from-scratch file is caught too; pass nullptr and this
// only establishes internal consistency, which is the weaker claim.
VerifyReport verify(const Record* records,
                    const uint8_t (*digests)[crypto::kSha256DigestLen],
                    size_t count, const void* seed, size_t seedLen,
                    const uint8_t* expectedHead = nullptr);

const char* verifyStatusName(VerifyStatus s);
const char* recordKindName(RecordKind k);

}  // namespace orthrus::evidence
