#include "chain.h"

#include <cstring>

namespace orthrus::evidence {

using crypto::kSha256DigestLen;

void serialise(const Record& r, uint8_t out[kSerialisedLen]) {
    size_t i = 0;
    out[i++] = static_cast<uint8_t>(r.seq & 0xFF);
    out[i++] = static_cast<uint8_t>((r.seq >> 8) & 0xFF);
    out[i++] = static_cast<uint8_t>((r.seq >> 16) & 0xFF);
    out[i++] = static_cast<uint8_t>((r.seq >> 24) & 0xFF);

    out[i++] = static_cast<uint8_t>(r.timeMs & 0xFF);
    out[i++] = static_cast<uint8_t>((r.timeMs >> 8) & 0xFF);
    out[i++] = static_cast<uint8_t>((r.timeMs >> 16) & 0xFF);
    out[i++] = static_cast<uint8_t>((r.timeMs >> 24) & 0xFF);

    out[i++] = static_cast<uint8_t>(r.kind);

    // Copy the detail exactly as declared, padding with NULs. Hashing only up
    // to the terminator would let two records with different trailing bytes
    // produce the same digest.
    std::memcpy(out + i, r.detail, kDetailLen);
}

void Chain::begin(const void* seed, size_t seedLen) {
    crypto::Sha256 h;
    // Domain separation, so a chain seed can never collide with a record hash.
    static const char kLabel[] = "orthrus/evidence/v1";
    h.update(kLabel, sizeof(kLabel));
    h.update(seed, seedLen);
    h.finish(head_);
    count_ = 0;
}

void Chain::append(const Record& r, uint8_t outHead[kSha256DigestLen]) {
    uint8_t body[kSerialisedLen];
    serialise(r, body);

    crypto::Sha256 h;
    h.update(head_, kSha256DigestLen);
    h.update(body, sizeof(body));
    h.finish(head_);

    count_++;
    if (outHead != nullptr) std::memcpy(outHead, head_, kSha256DigestLen);
}

VerifyReport verify(const Record* records,
                    const uint8_t (*digests)[kSha256DigestLen],
                    size_t count, const void* seed, size_t seedLen,
                    const uint8_t* expectedHead) {
    VerifyReport rep;

    if (records == nullptr || digests == nullptr || count == 0) {
        rep.status = VerifyStatus::Empty;
        return rep;
    }

    Chain chain;
    chain.begin(seed, seedLen);

    for (size_t i = 0; i < count; i++) {
        // Sequence numbers must run 0,1,2,... A gap means a record was removed
        // even if the remaining digests were recomputed to look tidy.
        if (records[i].seq != static_cast<uint32_t>(i)) {
            rep.status   = VerifyStatus::SequenceBroken;
            rep.failedAt = records[i].seq;
            rep.recordsOk = static_cast<uint32_t>(i);
            return rep;
        }

        uint8_t head[kSha256DigestLen];
        chain.append(records[i], head);

        if (!crypto::equalConstantTime(head, digests[i])) {
            rep.status    = VerifyStatus::DigestMismatch;
            rep.failedAt  = records[i].seq;
            rep.recordsOk = static_cast<uint32_t>(i);
            return rep;
        }
        rep.recordsOk++;
    }

    // Internally consistent. Whether that is worth anything depends on having
    // a head recorded away from the file.
    if (expectedHead != nullptr &&
        !crypto::equalConstantTime(chain.head(), expectedHead)) {
        rep.status   = VerifyStatus::HeadMismatch;
        rep.failedAt = static_cast<uint32_t>(count);
        return rep;
    }

    rep.status = VerifyStatus::Ok;
    return rep;
}

const char* verifyStatusName(VerifyStatus s) {
    switch (s) {
        case VerifyStatus::Ok:             return "ok";
        case VerifyStatus::Empty:          return "empty";
        case VerifyStatus::SequenceBroken: return "sequence broken";
        case VerifyStatus::DigestMismatch: return "digest mismatch";
        case VerifyStatus::HeadMismatch:   return "head mismatch";
    }
    return "?";
}

const char* recordKindName(RecordKind k) {
    switch (k) {
        case RecordKind::SessionStart: return "session-start";
        case RecordKind::Device:       return "device";
        case RecordKind::Finding:      return "finding";
        case RecordKind::Note:         return "note";
        case RecordKind::SessionEnd:   return "session-end";
    }
    return "?";
}

}  // namespace orthrus::evidence
