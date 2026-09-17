#include "ir_rx.h"

#include <M5Cardputer.h>
#include <driver/gpio.h>
#include <esp32-hal-rmt.h>

#include <cstring>

#include "board.h"

namespace orthrus::hal {

namespace {

// One RMT tick per microsecond. rmtSetTick takes NANOSECONDS, which is the
// single easiest thing to get wrong here -- 1000.0 is 1 us, not 1000 us.
constexpr float kTickNs = 1000.0f;

// Glitch filter, in source-clock ticks. Anything shorter than this is not part
// of a 38 kHz envelope; it is electrical noise, and letting it through turns
// one frame into two unusable ones.
constexpr uint32_t kFilterTicks = 100;

// The RMT idle threshold and the duration fields are both 15 bits.
constexpr uint32_t kRmtMaxTicks = 32767;

}  // namespace

// The RMT callback runs from the RMT driver's task, not an interrupt, so it is
// allowed to touch memory freely. It still does the minimum: unpack the
// hardware's items into durations and levels, and set a flag. Deciding what the
// frame MEANS happens on the UI task.
void IrRx::onFrame(uint32_t* data, size_t len, void* arg) {
    auto* c = static_cast<Channel*>(arg);
    if (c == nullptr || data == nullptr) return;

    c->frames++;

    // Already holding an undrained frame: keep the older one. A capture the
    // operator has not looked at yet is worth more than the one behind it.
    if (c->ready) return;

    uint16_t n = 0;
    bool overflowed = false;

    for (size_t i = 0; i < len; i++) {
        rmt_data_t item;
        item.val = data[i];

        // Each RMT item carries TWO intervals. A zero duration marks the end of
        // the frame, and everything after it is stale memory from a previous
        // capture rather than silence.
        const uint16_t d0 = static_cast<uint16_t>(item.duration0);
        if (d0 == 0) break;
        if (n >= ir::kMaxPulses) { overflowed = true; break; }
        c->us[n]    = d0;
        c->level[n] = (item.level0 != 0);
        n++;

        const uint16_t d1 = static_cast<uint16_t>(item.duration1);
        if (d1 == 0) break;
        if (n >= ir::kMaxPulses) { overflowed = true; break; }
        c->us[n]    = d1;
        c->level[n] = (item.level1 != 0);
        n++;
    }

    c->count    = n;
    c->overflow = overflowed;
    c->ready    = true;
}

bool IrRx::begin(int pinA, int pinB) {
    if (running_) return true;

    // The Grove port is the board's external I2C bus and the card reader claims
    // it. The peripheral has to let go of the pads before RMT can drive them.
    M5.Ex_I2C.release();

    const int pins[2] = {pinA, pinB};
    int claimed = 0;

    for (int i = 0; i < 2; i++) {
        Channel& c = chan_[i];
        c = Channel{};
        c.pin = pins[i];

        // Read the resting level before RMT takes the pin. Marks are defined as
        // the opposite of this, so an inverted receiver still yields a train
        // that starts with a mark.
        gpio_config_t cfg = {};
        cfg.pin_bit_mask = 1ULL << pins[i];
        cfg.mode         = GPIO_MODE_INPUT;
        // The unit supplies its own pull-up; this only decides what an
        // UNCONNECTED pin reads, which is what makes "no frames" mean "nothing
        // plugged in" rather than "floating and noisy".
        cfg.pull_up_en   = GPIO_PULLUP_ENABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
        cfg.intr_type    = GPIO_INTR_DISABLE;
        gpio_config(&cfg);
        delay(2);
        c.idleLevel = gpio_get_level(static_cast<gpio_num_t>(pins[i])) != 0;

        // 128 items is 256 intervals, comfortably past NEC's 67.
        rmt_obj_t* r = rmtInit(pins[i], RMT_RX_MODE, RMT_MEM_128);
        if (r == nullptr) continue;

        rmtSetTick(r, kTickNs);
        rmtSetFilter(r, true, kFilterTicks);
        rmtSetRxThreshold(r, kIdleUs > kRmtMaxTicks ? kRmtMaxTicks : kIdleUs);

        c.rmt = r;
        rmtRead(r, &IrRx::onFrame, &c);
        claimed++;
    }

    if (claimed == 0) {
        M5.Ex_I2C.begin(I2C_NUM_0, board::kGroveSda, board::kGroveScl);
        return false;
    }

    running_     = true;
    activePin_   = -1;
    framesSeen_  = 0;
    overruns_    = 0;
    haveLatched_ = false;
    return true;
}

void IrRx::end() {
    if (!running_) return;

    for (int i = 0; i < 2; i++) {
        if (chan_[i].rmt != nullptr) {
            rmtDeinit(static_cast<rmt_obj_t*>(chan_[i].rmt));
            chan_[i].rmt = nullptr;
        }
    }
    running_ = false;

    // Hand the Grove port back to I2C, symmetrically with the release() in
    // begin().
    //
    // This is not tidiness, it is a real defect if omitted: openSharedReader()
    // returns early when the reader already reports itself present, so it would
    // never re-initialise the bus -- and the card reader would silently stop
    // answering for the rest of the session, on every surface, with nothing on
    // screen to explain why.
    M5.Ex_I2C.begin(I2C_NUM_0, board::kGroveSda, board::kGroveScl);
}

uint32_t IrRx::framesOn(int pin) const {
    for (int i = 0; i < 2; i++)
        if (chan_[i].pin == pin) return chan_[i].frames;
    return 0;
}

bool IrRx::assemble(Channel& c) {
    const uint16_t n = c.count;
    const bool overflowed = c.overflow;

    if (overflowed) {
        overruns_++;
        c.ready = false;
        return false;
    }
    if (n < kMinPulses) {
        c.ready = false;
        return false;
    }

    // A pulse train starts with a MARK, which is whatever the line is NOT at
    // rest. Leading spaces are silence before the frame and carry nothing.
    const bool markLevel = !c.idleLevel;
    uint16_t start = 0;
    while (start < n && c.level[start] != markLevel) start++;
    if (n - start < kMinPulses) {
        c.ready = false;
        return false;
    }

    ir::PulseTrain t;
    t.count = 0;
    for (uint16_t i = start; i < n && t.count < ir::kMaxPulses; i++)
        t.us[t.count++] = c.us[i];

    latched_     = t;
    haveLatched_ = true;
    activePin_   = c.pin;
    framesSeen_++;
    c.ready = false;
    return true;
}

bool IrRx::poll() {
    if (!running_) return false;

    bool got = false;
    for (int i = 0; i < 2; i++) {
        if (!chan_[i].ready) continue;
        // One latch at a time: stop as soon as something is waiting to be
        // taken, so a second channel cannot overwrite it.
        if (haveLatched_) break;
        if (assemble(chan_[i])) got = true;
    }
    return got;
}

bool IrRx::take(ir::PulseTrain& out) {
    if (!haveLatched_) return false;
    out          = latched_;
    haveLatched_ = false;
    return true;
}

IrRx& sharedIrRx() {
    static IrRx instance;
    return instance;
}

}  // namespace orthrus::hal
