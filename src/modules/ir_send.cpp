#include "ir_send.h"

#include <M5Cardputer.h>

#include <cstdio>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;

namespace {

constexpr int kBodyTop = 21;
constexpr int kRowH    = 15;
constexpr int kLabelX  = 8;
constexpr int kValueX  = 150;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyLeft  = ',';
constexpr char kKeyRight = '/';
constexpr char kKeyBack  = '`';

constexpr int kProtocolCount = static_cast<int>(ir::Protocol::Rc5) + 1;

}  // namespace

bool IrSend::begin() {
    return tx_.begin();
}

void IrSend::adjust(int delta) {
    switch (field_) {
        case Field::Protocol: {
            int p = static_cast<int>(protocol_) + delta;
            while (p < 0) p += kProtocolCount;
            p %= kProtocolCount;
            protocol_ = static_cast<ir::Protocol>(p);

            // Changing protocol can put the current values out of range, and
            // silently masking them would send a different command than the one
            // on screen. Clamp visibly instead.
            if (address_ > ir::maxAddress(protocol_)) address_ = ir::maxAddress(protocol_);
            if (command_ > ir::maxCommand(protocol_)) command_ = ir::maxCommand(protocol_);
            break;
        }
        case Field::Address: {
            const int max = ir::maxAddress(protocol_);
            int v = static_cast<int>(address_) + delta;
            if (v < 0) v = max;
            if (v > max) v = 0;
            address_ = static_cast<uint16_t>(v);
            break;
        }
        case Field::Command: {
            const int max = ir::maxCommand(protocol_);
            int v = static_cast<int>(command_) + delta;
            if (v < 0) v = max;
            if (v > max) v = 0;
            command_ = static_cast<uint16_t>(v);
            break;
        }
        case Field::Repeats: {
            int v = static_cast<int>(repeats_) + delta;
            if (v < 1) v = 10;
            if (v > 10) v = 1;
            repeats_ = static_cast<uint8_t>(v);
            break;
        }
    }
}

void IrSend::transmit() {
    ir::PulseTrain train;
    lastOk_ = ir::encode(protocol_, address_, command_, train, rc5Toggle_);
    if (!lastOk_) return;

    // Flip only once the frame is known good, so a refused encode does not
    // silently consume a toggle and desynchronise the next real press.
    rc5Toggle_ = !rc5Toggle_;

    // Show the armed state before the emitter fires, not after. The frame takes
    // tens of milliseconds and the operator should see what is happening.
    ui::beginFrame();
    ui::chrome("Send", "SENDING");
    auto& d = ui::gfx();
    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_center);
    d.setTextColor(kShine, kInk);
    d.drawString("TRANSMITTING", bd::kScreenW / 2, 58);
    d.setFont(kFaceData);
    d.setTextColor(kMuted, kInk);
    char line[48];
    std::snprintf(line, sizeof(line), "%s  addr %04X  cmd %02X",
                  ir::protocolName(protocol_), address_, command_);
    d.drawString(line, bd::kScreenW / 2, 82);
    d.setTextDatum(top_left);
    ui::footer("emitter active");
    ui::endFrame();

    tx_.sendRepeated(train, protocol_, repeats_);
    tx_.idle();

    sent_++;
    lastSendMs_ = millis();

    // A transmission is an action taken against a target, so it belongs in the
    // engagement record whether or not anything visibly responded.
    char detail[96];
    std::snprintf(detail, sizeof(detail),
                  "ir=%s addr=%04X cmd=%02X repeats=%u",
                  ir::protocolName(protocol_), address_, command_,
                  static_cast<unsigned>(repeats_));
    app::recorder().noteFinding(detail);
}

void IrSend::draw() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%lu sent",
                  static_cast<unsigned long>(sent_));
    ui::chrome("Send", right);

    d.setFont(kFaceData);
    int y = kBodyTop + 6;

    const struct {
        Field       f;
        const char* label;
    } rows[] = {
        {Field::Protocol, "protocol"},
        {Field::Address,  "address"},
        {Field::Command,  "command"},
        {Field::Repeats,  "repeats"},
    };

    char v[4][24];
    std::snprintf(v[0], sizeof(v[0]), "%s", ir::protocolName(protocol_));
    std::snprintf(v[1], sizeof(v[1]), "0x%04X  (max %04X)", address_,
                  ir::maxAddress(protocol_));
    std::snprintf(v[2], sizeof(v[2]), "0x%02X  (max %02X)", command_,
                  ir::maxCommand(protocol_));
    std::snprintf(v[3], sizeof(v[3]), "%u", static_cast<unsigned>(repeats_));

    for (int i = 0; i < 4; i++) {
        const bool sel = (rows[i].f == field_);
        const int rowY = y + i * kRowH;
        ui::listRow(rowY - 5, kRowH, sel);

        ui::textAt(kLabelX, rowY, sel ? kShine : kMuted, "%s", rows[i].label);
        ui::textRight(kValueX, rowY, kText, "%s", v[i]);
    }

    y += 4 * kRowH + 2;
    d.drawFastHLine(6, y, bd::kScreenW - 12, kRule);

    if (!lastOk_) {
        ui::textAt(kLabelX, y + 10, kCritical, "Out of range for this protocol");
    } else if (millis() - lastSendMs_ < 1500 && sent_ > 0) {
        ui::textAt(kLabelX, y + 10, kGood, "Sent.");
    } else {
        ui::textAt(kLabelX, y + 10, kFaint, "Onboard emitter. Capture needs the IR unit.");
    }

    ui::footer("; . field   , / value   enter SEND   ` back");
    ui::endFrame();
}

bool IrSend::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    // Transmission is on Enter alone, and only ever fires one composed frame.
    if (ks.enter) {
        transmit();
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                tx_.idle();
                return false;
            case kKeyUp: {
                int f = static_cast<int>(field_) - 1;
                if (f < 0) f = 3;
                field_ = static_cast<Field>(f);
                return true;
            }
            case kKeyDown: {
                const int f = (static_cast<int>(field_) + 1) % 4;
                field_ = static_cast<Field>(f);
                return true;
            }
            case kKeyLeft:  adjust(-1); return true;
            case kKeyRight: adjust(+1); return true;
            // Coarse steps: stepping a 0..255 command one at a time is not a
            // usable way to find a code.
            case '[': adjust(-16); return true;
            case ']': adjust(+16); return true;
            default: break;
        }
    }
    return true;
}

void IrSend::run() {
    for (;;) {
        M5Cardputer.update();
        if (!handleKeys()) return;

        if (millis() - lastDrawMs_ >= 120) {
            lastDrawMs_ = millis();
            draw();
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
