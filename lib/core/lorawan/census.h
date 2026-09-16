// Device census: what we have heard, and how it behaved over time.
//
// A single frame is almost never a finding. "This device's frame counter went
// backwards" only exists across two frames, and "this device never joins" only
// exists across a whole capture. The census is where that history lives.
//
// Fixed-size and allocation-free by design: the board has 359 KB of heap and no
// PSRAM, and a scanner that grows its table until it dies in the field is worse
// than one that honestly reports it ran out of room.

#pragma once

#include <cstddef>
#include <cstdint>

#include "phy.h"

namespace orthrus::lorawan {

// Radio-side facts about one reception. The PHY parser cannot know these; they
// come from the SX1262.
struct RxMeta {
    uint32_t freqHz  = 0;
    uint8_t  sf      = 0;   // 7..12
    uint16_t bwKhz   = 0;   // 125 / 250 / 500
    int16_t  rssiDbm = 0;
    int8_t   snrDb   = 0;
    uint32_t timeMs  = 0;   // monotonic since boot
};

enum class DeviceKind : uint8_t {
    Session,  // identified by DevAddr, seen in data frames
    Joiner,   // identified by DevEUI, seen in join requests
};

// How many recent DevNonces to remember per joiner.
//
// LoRaWAN 1.0.x lets a device pick DevNonce randomly, so a repeat inside a
// short window is the signature of either a weak RNG or a replayed join. Eight
// is enough to catch both without costing real memory.
inline constexpr uint8_t kNonceHistory = 8;

struct DeviceRecord {
    DeviceKind kind = DeviceKind::Session;

    uint32_t devAddr = 0;        // Session
    uint8_t  devEui[8]  = {0};   // Joiner
    uint8_t  joinEui[8] = {0};   // Joiner

    uint32_t framesSeen  = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs  = 0;

    // --- frame counter behaviour (Session) ---
    uint16_t firstFCnt = 0;
    uint16_t lastFCnt  = 0;
    bool     haveFCnt  = false;
    uint32_t fcntResets  = 0;  // went backwards, and not a legitimate rollover
    uint32_t fcntRepeats = 0;  // exact same counter seen again
    uint32_t fcntRollovers = 0;
    uint16_t maxFCntJump = 0;

    // --- join behaviour (Joiner) ---
    uint32_t joinCount       = 0;
    uint32_t devNonceRepeats = 0;
    uint16_t nonceRing[kNonceHistory] = {0};
    uint8_t  nonceRingLen = 0;
    uint8_t  nonceRingPos = 0;

    // --- radio ---
    int16_t  bestRssiDbm = -200;
    int8_t   bestSnrDb   = -128;
    uint8_t  sfMin = 0xFF;
    uint8_t  sfMax = 0;
    uint32_t lastFreqHz = 0;

    // --- protocol flags, counted rather than latched, so "how often" survives ---
    uint32_t adrSetCount      = 0;
    uint32_t adrClearCount    = 0;
    uint32_t confirmedCount   = 0;
    uint32_t downlinkCount    = 0;
    uint32_t fPortZeroCount   = 0;
    uint32_t fPortZeroWithFOptsCount = 0;  // spec violation, see findings
    uint32_t plaintextCount   = 0;
    uint8_t  bestPlaintextConfidence = 0;

    uint32_t activeSpanMs() const {
        return lastSeenMs >= firstSeenMs ? lastSeenMs - firstSeenMs : 0;
    }
};

// What the capture as a whole looked like. Drives the confidence ceiling on any
// finding that argues from absence.
struct CaptureContext {
    uint32_t listenedMs       = 0;
    uint8_t  channelsCovered  = 1;   // how many channels we actually camped on
    uint8_t  channelsInRegion = 8;   // EU868 default; US915 is far worse
    uint8_t  sfCovered        = 1;
    uint8_t  sfInRegion       = 6;   // SF7..SF12

    // Fraction of the region's channel/SF space we could hear, in percent.
    // One SX1262 on one channel at one SF covers 1/48 of EU868 => 2%.
    uint8_t coveragePercent() const;
};

class Census {
public:
    // 128 records is about 13 KB -- affordable, and more devices than a single
    // channel/SF will realistically surface in one session.
    static constexpr size_t kMaxDevices = 128;

    void reset();

    // Folds one parsed frame into the census. Returns the index of the record
    // it landed in, or -1 if the frame was not trackable or the table is full.
    int observe(const Frame& frame, const RxMeta& meta);

    size_t size() const { return count_; }
    const DeviceRecord& at(size_t i) const { return devices_[i]; }

    uint32_t framesObserved() const { return framesObserved_; }
    uint32_t framesDropped() const { return framesDropped_; }
    uint32_t joinsObserved() const { return joinsObserved_; }

private:
    int findOrCreateSession(uint32_t devAddr);
    int findOrCreateJoiner(const uint8_t devEui[8]);

    DeviceRecord devices_[kMaxDevices];
    size_t       count_ = 0;

    uint32_t framesObserved_ = 0;
    uint32_t framesDropped_  = 0;
    uint32_t joinsObserved_  = 0;
};

// True when a 16-bit counter moving from `prev` to `next` is an honest
// wrap-around rather than a reset. Exposed because it is the single judgement
// that decides whether we accuse a device of opening a replay window.
bool isFCntRollover(uint16_t prev, uint16_t next);

}  // namespace orthrus::lorawan
