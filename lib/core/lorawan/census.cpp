#include "census.h"

#include <cstring>

#include "payload.h"

namespace orthrus::lorawan {

namespace {
// A rollover looks like a counter near the top wrapping to one near the bottom.
// The window is deliberately generous on the low side: we may miss frames (we
// hear one channel of many), so the first post-wrap frame we catch might be 30,
// not 0. It is deliberately tight on the high side, because that is what stops
// a reset from 0x8000 being excused as a wrap.
constexpr uint16_t kRolloverHighWater = 0xF000;
constexpr uint16_t kRolloverLowWater  = 0x0FFF;
}  // namespace

bool isFCntRollover(uint16_t prev, uint16_t next) {
    return prev >= kRolloverHighWater && next <= kRolloverLowWater;
}

void CounterTrack::observe(uint16_t fcnt) {
    if (!have) {
        first = fcnt;
        last  = fcnt;
        have  = true;
        return;
    }

    if (fcnt == last) {
        // Same counter twice: a retransmission after a missed ack, or a replay.
        // We cannot tell which from the air alone, and we do not pretend to.
        repeats++;
        return;
    }

    if (fcnt < last) {
        if (isFCntRollover(last, fcnt)) {
            rollovers++;
        } else {
            // Backwards without wrapping. For an ABP device this is a reboot,
            // and it reopens the replay window the counter exists to close.
            resets++;
        }
        last = fcnt;
        return;
    }

    const uint16_t jump = static_cast<uint16_t>(fcnt - last);
    if (jump > maxJump) maxJump = jump;
    last = fcnt;
}

uint8_t CaptureContext::coveragePercent() const {
    const uint32_t total = static_cast<uint32_t>(channelsInRegion ? channelsInRegion : 1) *
                           static_cast<uint32_t>(sfInRegion ? sfInRegion : 1);
    const uint32_t heard = static_cast<uint32_t>(channelsCovered) *
                           static_cast<uint32_t>(sfCovered);
    if (total == 0) return 0;
    uint32_t pct = (heard * 100u) / total;
    if (pct > 100) pct = 100;
    return static_cast<uint8_t>(pct);
}

void Census::reset() {
    count_          = 0;
    framesObserved_ = 0;
    framesDropped_  = 0;
    joinsObserved_  = 0;
}

int Census::findOrCreateSession(uint32_t devAddr) {
    for (size_t i = 0; i < count_; i++) {
        if (devices_[i].kind == DeviceKind::Session && devices_[i].devAddr == devAddr)
            return static_cast<int>(i);
    }
    if (count_ >= kMaxDevices) return -1;
    DeviceRecord& d = devices_[count_];
    d = DeviceRecord{};
    d.kind    = DeviceKind::Session;
    d.devAddr = devAddr;
    return static_cast<int>(count_++);
}

int Census::findOrCreateJoiner(const uint8_t devEui[8]) {
    for (size_t i = 0; i < count_; i++) {
        if (devices_[i].kind == DeviceKind::Joiner &&
            std::memcmp(devices_[i].devEui, devEui, 8) == 0)
            return static_cast<int>(i);
    }
    if (count_ >= kMaxDevices) return -1;
    DeviceRecord& d = devices_[count_];
    d = DeviceRecord{};
    d.kind = DeviceKind::Joiner;
    std::memcpy(d.devEui, devEui, 8);
    return static_cast<int>(count_++);
}

int Census::observe(const Frame& frame, const RxMeta& meta) {
    if (!frame.ok()) return -1;

    const bool trackable =
        (frame.mtype == MType::JoinRequest) || frame.isData();

    // Counted before anything can reject it. A frame we could not attribute or
    // had no room for was still heard, and a frame count that freezes when the
    // table fills makes a busy band look dead.
    framesObserved_++;

    if (!trackable) {
        // Join accepts are encrypted and carry no identity we can read;
        // proprietary and rejoin frames have no layout we can trust. Counting
        // them as traffic is honest, attributing them to a device is not.
        return -1;
    }

    const int idx = (frame.mtype == MType::JoinRequest)
                        ? findOrCreateJoiner(frame.join.devEui)
                        : findOrCreateSession(frame.data.devAddr);
    if (idx < 0) {
        framesDropped_++;
        return -1;
    }

    DeviceRecord& d = devices_[static_cast<size_t>(idx)];

    if (d.framesSeen == 0) d.firstSeenMs = meta.timeMs;
    d.lastSeenMs = meta.timeMs;
    d.framesSeen++;

    if (meta.rssiDbm > d.bestRssiDbm) d.bestRssiDbm = meta.rssiDbm;
    if (meta.snrDb > d.bestSnrDb) d.bestSnrDb = meta.snrDb;
    if (meta.sf != 0) {
        if (meta.sf < d.sfMin) d.sfMin = meta.sf;
        if (meta.sf > d.sfMax) d.sfMax = meta.sf;
    }
    if (meta.freqHz != 0) d.lastFreqHz = meta.freqHz;

    if (frame.mtype == MType::JoinRequest) {
        joinsObserved_++;
        d.joinCount++;
        std::memcpy(d.joinEui, frame.join.joinEui, 8);

        const uint16_t nonce = frame.join.devNonce;
        for (uint8_t i = 0; i < d.nonceRingLen; i++) {
            if (d.nonceRing[i] == nonce) {
                d.devNonceRepeats++;
                break;
            }
        }
        d.nonceRing[d.nonceRingPos] = nonce;
        d.nonceRingPos = static_cast<uint8_t>((d.nonceRingPos + 1) % kNonceHistory);
        if (d.nonceRingLen < kNonceHistory) d.nonceRingLen++;
        return idx;
    }

    // --- data frame ---
    const DataFields& f = frame.data;
    const bool uplink   = frame.isUplink();

    if (uplink) {
        d.uplinkCount++;
        // ADR and confirmation describe the device's own behaviour, so they are
        // only meaningful on frames the device sent.
        if (f.adr) d.adrSetCount++; else d.adrClearCount++;
        if (frame.isConfirmed()) d.confirmedUplinkCount++;
    } else {
        d.downlinkCount++;
    }

    if (f.hasFPort && f.fPort == 0) {
        d.fPortZeroCount++;
        // FPort 0 means the FRMPayload carries MAC commands. The spec forbids
        // also carrying MAC commands in FOpts at the same time; a device doing
        // both is either broken or being manipulated.
        if (f.fOptsLen > 0) d.fPortZeroWithFOptsCount++;
    }

    if (f.frmPayload != nullptr && f.frmPayloadLen > 0 && f.hasFPort && f.fPort != 0) {
        const PayloadVerdict v = inspectPayload(f.frmPayload, f.frmPayloadLen);
        if (v.looksPlaintext()) {
            d.plaintextCount++;
            if (v.confidence > d.bestPlaintextConfidence)
                d.bestPlaintextConfidence = v.confidence;
        }
    }

    // The counter goes into the track for its OWN direction. Mixing them was a
    // real bug that turned ordinary ACK traffic into a storm of false resets.
    (uplink ? d.up : d.down).observe(f.fCnt);

    return idx;
}

}  // namespace orthrus::lorawan
