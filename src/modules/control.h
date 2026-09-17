// Control: the infrared surface.
//
// Room control is a real part of a physical engagement -- projectors, displays,
// air conditioning and blinds all take IR, and all of them are unauthenticated
// by design. Orthrus composes a frame from a protocol, an address and a
// command, shows exactly what it is about to send, and sends it only when the
// operator presses the key.
//
// Single target, composed deliberately. There is no "send every code" mode and
// there will not be: blasting a library of power codes at a room is not
// assessment, and a tool that makes it one keypress away is a tool that gets
// used that way by accident.
//
// Transmit uses the onboard emitter on G44, so it needs no extra hardware.
// Capture would need the IR unit on a Grove port, and the screen says so rather
// than leaving an operator wondering why nothing is being received.

#pragma once

#include <cstdint>

#include "hal/ir_tx.h"
#include "ir/protocol.h"

namespace orthrus::modules {

class Control {
public:
    bool begin();
    void run();

private:
    enum class Field : uint8_t { Protocol, Address, Command, Repeats };

    void draw();
    bool handleKeys();
    void transmit();
    void adjust(int delta);

    hal::IrTx& tx_ = hal::sharedIrTx();

    ir::Protocol protocol_ = ir::Protocol::Nec;
    uint16_t     address_  = 0x00;
    uint16_t     command_  = 0x00;
    uint8_t      repeats_  = 3;

    // Flipped on every send. RC5 receivers use this bit to tell a new key
    // press from a held one; leaving it constant makes the second press look
    // like a continuation of the first and it gets dropped.
    bool         rc5Toggle_ = false;

    Field    field_       = Field::Protocol;
    uint32_t lastSendMs_  = 0;
    uint32_t sent_        = 0;
    bool     lastOk_      = true;
    uint32_t lastDrawMs_  = 0;
};

}  // namespace orthrus::modules
