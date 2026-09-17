// Clone: copy a badge onto a blank you own.
//
// The single most convincing demonstration in physical security. A client who
// has read that their badges are copyable has read a sentence; a client who
// watches their own door open for a card that was blank two minutes ago has
// understood the problem.
//
// HOW IT IS KEPT HONEST
//
//   The original is NEVER written to. It is read, it leaves the reader exactly
//   as it arrived, and the code that could write to it refuses block 0 unless
//   the card has already answered the magic backdoor -- which a real badge
//   does not.
//
//   The destination must prove it is a blank. Gen1a "magic" cards answer an
//   undocumented backdoor command; normal cards ignore it entirely. That probe
//   is harmless and happens BEFORE anything is armed, so pointing this at
//   somebody's real badge by mistake fails safe.
//
//   Reading and writing are separate steps with the card physically swapped in
//   between, so there is a moment where the operator has to put one card down
//   and pick another up. That is not friction for its own sake -- it is the
//   difference between a clone and an accident.
//
// WHAT IT CANNOT DO
//
// Only sectors that open with a published key can be read, so only those can be
// copied. A badge that was properly configured yields its UID and little else,
// and the screen says exactly how much of it came across rather than reporting
// a clone that is mostly zeroes.

#pragma once

#include <cstdint>

#include "credential/tag.h"
#include "hal/rfid2.h"

namespace orthrus::modules {

class RfidClone {
public:
    RfidClone();

    bool begin();
    void run();

private:
    enum class View : uint8_t {
        WaitSource,   // present the badge to copy
        Reading,      // pulling what we can off it
        Source,       // what we got, and what we did not
        WaitBlank,    // present the magic card
        Writing,
        Result,
    };

    static constexpr uint8_t kMaxSectors = 16;   // 1K; a 4K source copies its first 1K
    static constexpr uint8_t kBlocksPerSector = 4;

    struct SectorCopy {
        bool    read = false;
        uint8_t data[kBlocksPerSector][16] = {{0}};
    };

    void pollSource();
    void stepRead();
    void pollBlank();
    void stepWrite();

    void drawWaitSource();
    void drawReading();
    void drawSource();
    void drawWaitBlank();
    void drawWriting();
    void drawResult();
    bool handleKeys();

    hal::Rfid2& reader_;

    credential::TagIdentity source_;
    bool       haveSource_ = false;
    SectorCopy sectors_[kMaxSectors];
    uint8_t    sectorTotal_ = 0;
    uint8_t    readAt_      = 0;
    uint8_t    sectorsRead_ = 0;
    bool       reading_     = false;

    // The destination.
    credential::TagIdentity blank_;
    bool     blankIsMagic_ = false;
    bool     blankSeen_    = false;

    bool     armed_    = false;
    bool     writing_  = false;
    uint8_t  writeAt_  = 0;
    uint8_t  blocksWritten_ = 0;
    uint8_t  blocksFailed_  = 0;
    bool     uidWritten_    = false;

    View     view_       = View::WaitSource;
    uint32_t lastPollMs_ = 0;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
