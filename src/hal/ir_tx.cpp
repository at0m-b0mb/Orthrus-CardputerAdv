#include "ir_tx.h"

#include <Arduino.h>
#include <esp_timer.h>

#include "board.h"

namespace orthrus::hal {
namespace {

constexpr int kLedcChannel = 4;   // away from anything the audio path may use
constexpr int kLedcBits    = 8;
constexpr int kDutyHalf    = 128; // 50% of an 8-bit range

// Busy-wait to an absolute microsecond deadline.
//
// delayMicroseconds() measures against the FreeRTOS tick, which is far too
// coarse for a 560 us pulse. Working to an absolute deadline also means an
// interrupt in the middle of one pulse does not push every later pulse late --
// the error stays local instead of accumulating across the frame.
inline void waitUntil(int64_t deadlineUs) {
    while (esp_timer_get_time() < deadlineUs) {
        // Spin. Yielding here would hand control to a scheduler that cannot
        // return inside a microsecond.
    }
}

}  // namespace

bool IrTx::begin() {
    if (ready_) return true;
    ledcSetup(kLedcChannel, 38000, kLedcBits);
    ledcAttachPin(board::kIrEmitter, kLedcChannel);
    ledcWrite(kLedcChannel, 0);
    ready_ = true;
    return true;
}

void IrTx::send(const ir::PulseTrain& train) {
    if (!ready_ || train.count == 0) return;

    // Each protocol has its own carrier; Sony is 40 kHz and RC5 36 kHz, and a
    // receiver tuned for one rejects a frame sent on another.
    ledcSetup(kLedcChannel, train.carrierHz, kLedcBits);
    ledcWrite(kLedcChannel, 0);

    int64_t deadline = esp_timer_get_time();
    for (uint8_t i = 0; i < train.count; i++) {
        // Even indices are marks (carrier on), odd are spaces.
        ledcWrite(kLedcChannel, (i % 2 == 0) ? kDutyHalf : 0);
        deadline += train.us[i];
        waitUntil(deadline);
    }

    ledcWrite(kLedcChannel, 0);
    framesSent_++;
}

void IrTx::sendRepeated(const ir::PulseTrain& train, ir::Protocol p,
                        uint8_t repeats) {
    if (repeats == 0) repeats = 1;
    const uint32_t gap = ir::repeatGapUs(p);

    for (uint8_t i = 0; i < repeats; i++) {
        send(train);
        if (i + 1 < repeats) {
            // The gap is measured frame start to frame start, so subtract what
            // the frame itself already took. Sending faster than the protocol
            // allows is a common way to get ignored.
            const uint32_t spent = train.durationUs();
            const uint32_t rest  = gap > spent ? gap - spent : 1000;
            delay(rest / 1000);
            delayMicroseconds(rest % 1000);
        }
    }
}

void IrTx::idle() {
    if (ready_) ledcWrite(kLedcChannel, 0);
}

IrTx& sharedIrTx() {
    static IrTx instance;
    return instance;
}

}  // namespace orthrus::hal
