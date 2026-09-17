// Credentials: the 13.56 MHz badge surface.
//
// Hold a badge against the reader and it tells you what the card is, what it
// relies on for security, and how hard it would be to copy -- all from
// anticollision alone, which is exactly what an attacker in a lift gets.
//
// The reader can be on either Grove port. The Cardputer-Adv has its own Port A
// on G1/G2, and the LoRa cap adds a second on G8/G9, so both units can be
// connected at once.

#pragma once

#include <cstdint>

#include "credential/grade.h"
#include "credential/tag.h"
#include "hal/rfid2.h"

namespace orthrus::modules {

class Credentials {
public:
    bool begin();
    void run();

    // Which bus the reader answered on, for the status line.
    const char* busName() const { return busName_; }

private:
    enum class View : uint8_t { Waiting, Card, Dossier, Roll };

    void poll();
    void drawWaiting();
    void drawCard();
    void drawDossier();
    void drawRoll();
    bool handleKeys();
    void runKeyProbe();

    // A small roll of what has been presented this session. A physical
    // engagement means walking past a lot of people; being able to look back at
    // the third badge without having asked them to tap again matters.
    static constexpr uint8_t kRollMax = 12;

    struct Seen {
        credential::TagIdentity tag;
        uint32_t firstMs = 0;
        uint32_t count   = 0;
    };

    int findInRoll(const credential::TagIdentity& t) const;

    hal::Rfid2 reader_;
    const char* probeNote_ = nullptr;
    char        probeBuf_[64] = {0};
    const char* busName_ = "none";

    Seen    roll_[kRollMax];
    uint8_t rollCount_ = 0;
    int     selected_  = 0;

    View     view_        = View::Waiting;
    uint32_t lastDrawMs_  = 0;
    uint32_t lastPollMs_  = 0;
    uint32_t lastReadMs_  = 0;
    uint32_t pollCount_   = 0;
    uint32_t errorCount_  = 0;
    hal::ReaderStatus lastStatus_ = hal::ReaderStatus::NoCard;
};

}  // namespace orthrus::modules
