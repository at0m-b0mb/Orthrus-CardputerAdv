// The engagement record.
//
// One append-only file per session on the microSD, with every line carrying the
// running hash-chain digest. Edit, insert, delete or reorder anything in it and
// every digest after that point stops matching.
//
// This is what makes a capture a deliverable rather than an anecdote, and it is
// the reason the chain in lib/core/evidence exists. Anything worth telling a
// client goes through here.
//
// The honest limit, repeated because it matters: a keyless chain cannot stop
// someone who rewrites the whole file and recomputes every digest. What closes
// that is recording the head digest somewhere the file cannot reach -- which is
// why the Engagement screen puts it on the panel for the operator to
// photograph. Verified against a head recorded that way, the log is genuinely
// tamper-evident.

#pragma once

#include <cstdint>

#include "evidence/chain.h"

namespace orthrus::app {

class Recorder {
public:
    // Mounts the card and opens a new session file. Safe to call repeatedly;
    // only the first call does anything.
    bool begin();

    bool active() const { return active_; }

    // Appends one record. Returns false if there is no card, or the write
    // failed -- and a failed write is NOT chained, so the file on the card and
    // the digest in memory can never disagree.
    bool note(evidence::RecordKind kind, const char* detail);

    // Convenience for the common shapes, so call sites stay readable.
    bool noteDevice(const char* detail) {
        return note(evidence::RecordKind::Device, detail);
    }
    bool noteFinding(const char* detail) {
        return note(evidence::RecordKind::Finding, detail);
    }

    uint32_t    count() const { return chain_.count(); }
    const char* path() const { return path_; }
    const char* lastError() const { return lastError_; }

    // The head digest, hex, NUL-terminated. 65 bytes required.
    void headHex(char out[65]) const;

    // Short form for the panel: first 8 and last 8 hex characters. A 64
    // character digest does not fit on a 240 px screen, and an operator
    // copying it down needs something they can actually transcribe.
    void headShort(char out[24]) const;

private:
    bool openSessionFile();

    evidence::Chain chain_;
    bool        active_    = false;
    char        path_[40]  = {0};
    char        seed_[48]  = {0};
    const char* lastError_ = "";
    uint32_t    failures_  = 0;
    bool        attempted_ = false;
};

// One recorder for the whole device: every surface writes into the same
// session, because an engagement is one engagement.
Recorder& recorder();

}  // namespace orthrus::app
