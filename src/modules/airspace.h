// Airspace: the live LoRa listening surface.
//
// Three views, one loop:
//   Live    -- what the radio is hearing right now, and how much it cannot hear
//   Census  -- every device heard this session, graded
//   Dossier -- why a given device earned that grade
//
// Hopping is the interesting part. A single radio parked on one channel at one
// spreading factor covers 1/48 of EU868. Sweeping the channels raises that to
// 8/48, and the coverage grid shows it filling in, so the operator can watch
// their own blind spot shrink instead of being told about it.

#pragma once

#include <cstdint>

#include "hal/gnss.h"
#include "hal/lora_radio.h"
#include "lorawan/census.h"
#include "lorawan/findings.h"
#include "lorawan/region.h"
#include "spectrum.h"

namespace orthrus::modules {

class Airspace {
public:
    bool begin();
    void run();  // returns when the operator backs out

private:
    enum class View : uint8_t { Live, Census, Dossier, Spectrum };

    void pump();          // service the radio, fold frames into the census
    void retune();        // apply current channel/SF to the radio
    void advanceHop();

    void drawLive();
    void drawCensus();
    void drawDossier();
    void drawSpectrum();

    bool handleKeys();    // false = leave the module

    lorawan::CaptureContext context() const;
    uint8_t coveredChannels() const;
    uint8_t coveredSpreadingFactors() const;

    // A live trace of the receiver's own noise floor.
    //
    // The first build showed only counters that move when a LoRaWAN frame
    // arrives. With no gateway nearby every number stayed at zero and a
    // perfectly working radio looked dead. This always moves, because the
    // receiver always has a floor.
    static constexpr uint8_t kTraceLen = 58;
    int8_t   rssiTrace_[kTraceLen] = {0};
    uint8_t  rssiPos_   = 0;
    bool     traceFull_ = false;
    uint32_t lastRssiMs_ = 0;
    float    rssiNow_   = 0.0f;

    void sampleRssi();
    void logDevice(const lorawan::DeviceRecord& rec,
                   const lorawan::RxMeta& meta);

    hal::Gnss&        gnss_  = hal::sharedGnss();
    hal::LoraRadio&   radio_ = hal::sharedRadio();
    Spectrum          spectrum_;
    lorawan::Census   census_;
    lorawan::Region   region_ = lorawan::Region::EU868;

    View     view_       = View::Live;
    uint8_t  chIndex_    = 0;
    uint8_t  sfIndex_    = 0;
    bool     hopping_    = true;
    uint32_t lastHopMs_  = 0;
    uint32_t hopDwellMs_ = 2500;

    uint32_t startedMs_  = 0;
    uint32_t lastDrawMs_ = 0;

    // Which (channel, SF) pairs we have actually camped on. One bit per pair,
    // so coverage is a popcount rather than a guess.
    uint64_t visitedChannels_ = 0;
    uint64_t visitedSfs_      = 0;

    // Most recent decode, for the live view.
    char     lastLine_[40] = {0};
    uint32_t lastFrameMs_  = 0;
    uint32_t parseFailures_ = 0;

    int selected_ = 0;  // census cursor
    int scroll_   = 0;
};

}  // namespace orthrus::modules
