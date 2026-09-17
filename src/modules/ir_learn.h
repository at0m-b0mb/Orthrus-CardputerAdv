// Learn: capture a real remote's code, name it, and send it back.
//
// Send composes a frame from a protocol, an address and a command you already
// know. That covers the case where the target is a common TV. It does not cover
// the case an engagement actually hits: a projector, a door controller or an AC
// unit whose codes are in nobody's database. For those, the remote is sitting
// on the table, and the fastest route is to listen to it.
//
// WHAT IT NEEDS
//
// The Cardputer-Adv has an emitter and no receiver, so this needs the IR unit
// on Grove Port A. Which of the port's two signal lines carries the receiver
// output depends on the unit and the cable, so the HAL listens on BOTH and
// reports which answered -- and the screen shows edge counts per pin, so "the
// unit is not plugged in" and "the remote's battery is flat" look different.
//
// REPLAY IS RE-ENCODED WHEN IT CAN BE
//
// A captured train carries the receiver's own bias: these modules stretch marks
// and shorten spaces by fifty to a hundred microseconds. Replaying those
// timings verbatim works, but it sends a slightly wrong frame and then hands
// its own error to the next device in the chain. So when a capture decodes, the
// replay is re-encoded from the decoded protocol, address and command -- clean
// timings, and provably the same button. Only an undecoded capture is replayed
// raw, and the screen says which of the two it is about to do.

#pragma once

#include <cstdint>

#include "hal/ir_rx.h"
#include "hal/ir_tx.h"
#include "ir/protocol.h"

namespace orthrus::modules {

class IrLearn {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { Listening, List, Detail, Saved };

    static constexpr uint8_t kMaxCaptures = 8;

    struct Capture {
        ir::PulseTrain train;
        ir::Decoded    decoded;
        bool           recognised = false;
        uint32_t       atMs       = 0;
        uint8_t        repeats    = 0;   // held-key frames folded into this one
    };

    void pump();
    void store(const ir::PulseTrain& t);
    void replay();
    bool saveAll();

    void drawListening();
    void drawList();
    void drawDetail();
    void drawSaved();
    bool handleKeys();

    hal::IrRx& rx_ = hal::sharedIrRx();
    hal::IrTx& tx_ = hal::sharedIrTx();

    Capture  captures_[kMaxCaptures];
    uint8_t  count_    = 0;
    int      selected_ = 0;

    bool     started_  = false;
    uint32_t enteredMs_ = 0;

    // Replay feedback.
    bool     lastReplayEncoded_ = false;
    uint32_t lastReplayMs_      = 0;

    char     savePath_[48] = {0};
    bool     saveOk_       = false;
    uint8_t  savedCount_   = 0;

    View     view_       = View::Listening;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
