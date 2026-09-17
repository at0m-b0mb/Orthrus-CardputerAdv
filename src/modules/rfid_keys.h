// Keys: how much of a Mifare Classic badge is still behind a factory key.
//
// Credentials answers "what is this badge and how exposed is it" from
// anticollision alone. This answers the question a client actually asks next:
// open it. Every sector, both key types, every published key, and then read
// what is behind the ones that opened.
//
// The difference matters. A site that left the factory key on sector 0 and
// diversified the rest has a different problem from a site that left all
// sixteen -- and a report that says "default key accepted" without saying how
// much of the card it accepts on cannot tell them apart.
//
// READ ONLY, LIKE EVERYTHING ELSE HERE
//
// This authenticates and reads. It never writes a block, never changes a key,
// never touches an access condition. A badge that leaves the reader is byte for
// byte the badge that arrived on it. That is not timidity: an authorized test
// that bricks somebody's access card is a failed test.
//
// AND IT IS NOT A CRACKER
//
// No nested attack, no darkside, no hardnested. If a sector does not open with
// a published key, the honest answer is "we could not open it" -- not a longer
// grind that eventually claims a key this device never actually recovered.

#pragma once

#include <cstdint>

#include "credential/tag.h"
#include "hal/rfid2.h"

namespace orthrus::modules {

class RfidKeys {
public:
    RfidKeys();

    bool begin();
    void run();

private:
    enum class View : uint8_t { Waiting, Card, Sweeping, Map, Sector, Saved };

    // 40 sectors covers a 4K card. A 1K card uses the first sixteen.
    static constexpr uint8_t kMaxSectors = 40;
    // Four blocks held per sector: three of data and the trailer. A 4K card's
    // last eight sectors hold sixteen blocks; only the first four are kept, and
    // the screen says so rather than implying the sector was fully dumped.
    static constexpr uint8_t kBlocksKept = 4;

    struct SectorResult {
        bool    opened     = false;
        bool    attempted  = false;
        uint8_t keyIndex   = 0;
        uint8_t keyType    = 0;   // 0 = key A, 1 = key B
        uint8_t blocksRead = 0;
        uint8_t data[kBlocksKept][16] = {{0}};
    };

    void pollCard();
    void startSweep();
    void stepSweep();
    bool saveDump();

    void drawWaiting();
    void drawCard();
    void drawSweeping();
    void drawMap();
    void drawSector();
    void drawSaved();
    bool handleKeys();

    void sectorGrid(int x, int y, int maxWidth);

    hal::Rfid2& reader_;

    credential::TagIdentity tag_;
    bool    haveCard_ = false;

    SectorResult sectors_[kMaxSectors];
    uint8_t sectorTotal_ = 0;
    uint8_t sweepAt_     = 0;
    uint8_t opened_      = 0;
    bool    sweeping_    = false;
    bool    cardLost_    = false;

    int  selected_ = 0;
    View view_     = View::Waiting;

    char     dumpPath_[40] = {0};
    bool     saveOk_       = false;
    uint16_t savedBlocks_  = 0;

    uint32_t lastPollMs_ = 0;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
