#include "ir_learn.h"

#include <M5Cardputer.h>
#include <SD.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;

namespace {

constexpr uint32_t kRedrawMs = 160;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyBack  = '`';
constexpr char kKeySave  = 's';
constexpr char kKeyClear = 'c';

// Two frames of the same button arriving within this window are a held key, not
// two presses. Folding them keeps the list readable -- a remote held for a
// second would otherwise fill all eight slots with the same code.
constexpr uint32_t kRepeatWindowMs = 900;

bool sameCode(const ir::Decoded& a, const ir::Decoded& b) {
    return a.protocol == b.protocol && a.address == b.address &&
           a.command == b.command;
}

}  // namespace

bool IrLearn::begin() {
    count_     = 0;
    selected_  = 0;
    view_      = View::Listening;
    enteredMs_ = millis();

    tx_.begin();
    // The receiver is documented to be the white wire on G1 (see board.h), so
    // that is tried as channel 0. Both lines are still listened to, because a
    // cable wired the other way round is a five second mistake that would
    // otherwise present as a dead screen.
    started_ = rx_.begin(bd::kIrUnitRx, bd::kIrUnitTx);
    return true;   // a failed receiver is a state the screen explains, not a refusal
}

void IrLearn::pump() {
    if (!started_) return;
    if (!rx_.poll()) return;

    ir::PulseTrain t;
    while (rx_.take(t)) store(t);
}

void IrLearn::store(const ir::PulseTrain& t) {
    ir::Decoded d;
    const bool ok = ir::decode(t, d);

    // A NEC repeat frame carries no data at all -- it means the key is still
    // down. Attaching it to the previous capture is the only useful thing to do
    // with it; storing it on its own would be a row that cannot be replayed.
    if (ok && d.repeat) {
        if (count_ > 0) captures_[count_ - 1].repeats++;
        return;
    }

    if (count_ > 0) {
        Capture& last = captures_[count_ - 1];
        if (ok && last.recognised && sameCode(last.decoded, d) &&
            millis() - last.atMs < kRepeatWindowMs) {
            last.repeats++;
            last.atMs = millis();
            return;
        }
    }

    if (count_ >= kMaxCaptures) {
        // Evict the oldest. An operator pressing a ninth button wants the ninth
        // button, not a refusal.
        for (uint8_t i = 1; i < kMaxCaptures; i++) captures_[i - 1] = captures_[i];
        count_ = kMaxCaptures - 1;
        if (selected_ > 0) selected_--;
    }

    Capture& c = captures_[count_++];
    c.train      = t;
    c.decoded    = d;
    c.recognised = ok;
    c.atMs       = millis();
    c.repeats    = 0;

    if (view_ == View::Listening) view_ = View::List;
    selected_ = count_ - 1;

    char detail[96];
    if (ok) {
        std::snprintf(detail, sizeof(detail), "ir learn %s addr=%04x cmd=%04x",
                      ir::protocolName(d.protocol),
                      static_cast<unsigned>(d.address),
                      static_cast<unsigned>(d.command));
    } else {
        std::snprintf(detail, sizeof(detail), "ir learn raw pulses=%u",
                      static_cast<unsigned>(t.count));
    }
    app::recorder().noteDevice(detail);
}

void IrLearn::replay() {
    if (count_ == 0 || selected_ < 0 || selected_ >= static_cast<int>(count_)) return;
    const Capture& c = captures_[selected_];

    // The receiver would otherwise hear our own emitter and file the replay as
    // a fresh capture. Suspending it is simpler than filtering, and it also
    // stops the list filling up every time a code is tested.
    const bool wasRunning = rx_.running();
    if (wasRunning) rx_.end();

    if (c.recognised) {
        // Re-encoded rather than replayed verbatim: a captured train carries
        // the receiver's own bias, and sending that bias on is passing our
        // measurement error to the target.
        ir::PulseTrain clean;
        if (ir::encode(c.decoded.protocol, c.decoded.address, c.decoded.command,
                       clean, c.decoded.toggle)) {
            tx_.sendRepeated(clean, c.decoded.protocol, 3);
            lastReplayEncoded_ = true;
        } else {
            tx_.send(c.train);
            lastReplayEncoded_ = false;
        }
    } else {
        tx_.send(c.train);
        lastReplayEncoded_ = false;
    }
    lastReplayMs_ = millis();

    if (wasRunning) started_ = rx_.begin(bd::kIrUnitRx, bd::kIrUnitTx);
}

bool IrLearn::saveAll() {
    saveOk_     = false;
    savedCount_ = 0;
    if (count_ == 0) return false;

    if (!app::recorder().begin() && !app::recorder().active()) return false;
    if (!SD.exists("/orthrus")) SD.mkdir("/orthrus");

    for (int i = 1; i < 1000; i++) {
        std::snprintf(savePath_, sizeof(savePath_), "/orthrus/ir-%03d.txt", i);
        if (!SD.exists(savePath_)) break;
        savePath_[0] = '\0';
    }
    if (savePath_[0] == '\0') return false;

    File f = SD.open(savePath_, FILE_WRITE);
    if (!f) return false;

    f.println("# Orthrus -- captured infrared codes");
    f.println("# raw = microsecond mark/space durations, starting with a mark.");

    for (uint8_t i = 0; i < count_; i++) {
        const Capture& c = captures_[i];
        f.printf("\n[%u]\n", static_cast<unsigned>(i + 1));
        if (c.recognised) {
            f.printf("protocol=%s\naddress=0x%04x\ncommand=0x%04x\n",
                     ir::protocolName(c.decoded.protocol),
                     static_cast<unsigned>(c.decoded.address),
                     static_cast<unsigned>(c.decoded.command));
            if (c.decoded.protocol == ir::Protocol::Rc5)
                f.printf("toggle=%d\n", c.decoded.toggle ? 1 : 0);
        } else {
            f.println("protocol=unrecognised");
        }
        f.printf("carrier=%u\nrepeats=%u\nraw=", static_cast<unsigned>(c.train.carrierHz),
                 static_cast<unsigned>(c.repeats));
        for (uint8_t k = 0; k < c.train.count; k++)
            f.printf("%u%s", static_cast<unsigned>(c.train.us[k]),
                     k + 1 < c.train.count ? "," : "\n");
        savedCount_++;
    }
    f.close();

    char detail[96];
    std::snprintf(detail, sizeof(detail), "ir export codes=%u file=%s",
                  static_cast<unsigned>(savedCount_), savePath_);
    app::recorder().note(evidence::RecordKind::Note, detail);

    saveOk_ = true;
    return true;
}

// ---- screens -----------------------------------------------------------------

void IrLearn::drawListening() {
    ui::beginFrame();
    auto& d = ui::gfx();

    ui::chrome("Learn", started_ ? "listening" : "no pins");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (!started_) {
        d.setTextColor(kCritical, kInk);
        d.drawString("Could not claim Port A.", 8, kBodyTop + 8);
        ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 3, kMuted,
                     "Something else is holding the Grove pins. Leave and "
                     "re-enter this screen.");
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    d.setTextColor(kText, kInk);
    d.drawString("Point a remote at the unit", 8, kBodyTop + 6);
    d.drawString("and press a button.", 8, kBodyTop + 18);

    // Edge counts per pin, which is the whole diagnostic. A pin with edges but
    // no frames is hearing something that is not a remote; both pins silent
    // means the unit is not on this port.
    const uint32_t eScl = rx_.framesOn(bd::kIrUnitRx);
    const uint32_t eSda = rx_.framesOn(bd::kIrUnitTx);

    d.drawFastHLine(6, kBodyTop + 32, bd::kScreenW - 12, kRule);
    ui::textAt(8, kBodyTop + 42, eScl ? kShine : kFaint, "G%d (white) %lu frames",
               bd::kIrUnitRx, static_cast<unsigned long>(eScl));
    ui::textAt(8, kBodyTop + 54, eSda ? kShine : kFaint, "G%d (yellow) %lu",
               bd::kIrUnitTx, static_cast<unsigned long>(eSda));

    if (eScl == 0 && eSda == 0 && millis() - enteredMs_ > 6000) {
        ui::wrapText(8, kBodyTop + 68, bd::kScreenW - 16, 10, 2, kMuted,
                     "Nothing on either line. Check the unit is on the Grove "
                     "port.");
    } else if (rx_.overruns()) {
        ui::textAt(8, kBodyTop + 68, kHigh, "%lu frames too long to store",
                   static_cast<unsigned long>(rx_.overruns()));
    }

    ui::footer("` back");
    ui::endFrame();
}

void IrLearn::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[20];
    if (rx_.activePin() >= 0)
        std::snprintf(right, sizeof(right), "G%d  %u", rx_.activePin(),
                      static_cast<unsigned>(count_));
    else
        std::snprintf(right, sizeof(right), "%u", static_cast<unsigned>(count_));
    ui::chrome("Learn", right);

    if (selected_ >= static_cast<int>(count_)) selected_ = count_ - 1;
    if (selected_ < 0) selected_ = 0;

    for (int i = 0; i < kRows && i < static_cast<int>(count_); i++) {
        const Capture& c = captures_[i];
        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (i == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);

        if (c.recognised) {
            d.setTextColor(kText, bg);
            d.drawString(ir::protocolName(c.decoded.protocol), 8, mid);
            d.setTextColor(kShine, bg);
            char code[24];
            std::snprintf(code, sizeof(code), "%04x:%04x",
                          static_cast<unsigned>(c.decoded.address),
                          static_cast<unsigned>(c.decoded.command));
            d.drawString(code, 76, mid);
        } else {
            d.setTextColor(kMuted, bg);
            d.drawString("raw", 8, mid);
            char n[20];
            std::snprintf(n, sizeof(n), "%u pulses",
                          static_cast<unsigned>(c.train.count));
            d.drawString(n, 76, mid);
        }

        if (c.repeats) {
            d.setTextDatum(middle_right);
            d.setTextColor(kFaint, bg);
            char r[12];
            std::snprintf(r, sizeof(r), "x%u", static_cast<unsigned>(c.repeats + 1));
            d.drawString(r, bd::kScreenW - 6, mid);
        }
    }

    d.setTextDatum(top_left);
    if (lastReplayMs_ && millis() - lastReplayMs_ < 1500) {
        ui::textAt(8, bd::kScreenH - kFooterH - 11,
                   lastReplayEncoded_ ? kGood : kMedium,
                   lastReplayEncoded_ ? "sent, re-encoded" : "sent, raw replay");
    }
    ui::footer("enter send  s save  c clear  ` back");
    ui::endFrame();
}

void IrLearn::drawDetail() {
    if (count_ == 0) {
        view_ = View::List;
        return;
    }
    if (selected_ >= static_cast<int>(count_)) selected_ = count_ - 1;

    ui::beginFrame();
    auto& d = ui::gfx();
    const Capture& c = captures_[selected_];

    ui::chrome("Code", c.recognised ? ir::protocolName(c.decoded.protocol) : "raw");

    d.setFont(kFaceData);

    if (c.recognised) {
        ui::textAt(8, kBodyTop + 5, kText, "address  0x%04x",
                   static_cast<unsigned>(c.decoded.address));
        ui::textAt(8, kBodyTop + 17, kText, "command  0x%04x",
                   static_cast<unsigned>(c.decoded.command));
        ui::textAt(8, kBodyTop + 29, kFaint, "carrier  %u Hz",
                   static_cast<unsigned>(ir::carrierFor(c.decoded.protocol)));
        if (c.decoded.protocol == ir::Protocol::Rc5)
            ui::textRight(bd::kScreenW - 6, kBodyTop + 29, kFaint, "toggle %d",
                          c.decoded.toggle ? 1 : 0);
    } else {
        ui::textAt(8, kBodyTop + 5, kMedium, "Not a protocol we decode.");
        ui::wrapText(8, kBodyTop + 18, bd::kScreenW - 16, 10, 2, kFaint,
                     "It can still be replayed exactly as captured.");
    }

    d.drawFastHLine(6, kBodyTop + 40, bd::kScreenW - 12, kRule);

    // The first few intervals, so an operator can see it really is a frame and
    // not a burst of noise that happened to decode.
    ui::textAt(8, kBodyTop + 48, kFaint, "%u pulses",
               static_cast<unsigned>(c.train.count));
    char row[44] = {0};
    int w = 0;
    for (uint8_t i = 0; i < c.train.count && i < 6; i++)
        w += std::snprintf(row + w, sizeof(row) - w, "%u ",
                           static_cast<unsigned>(c.train.us[i]));
    ui::textAt(8, kBodyTop + 60, kMuted, "%s...", row);

    d.setTextDatum(top_left);
    ui::footer("enter send   ; . code   ` back");
    ui::endFrame();
}

void IrLearn::drawSaved() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Export");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (!saveOk_) {
        d.setTextColor(kCritical, kInk);
        d.drawString("Could not write to the card.", 8, kBodyTop + 8);
        d.setTextColor(kMuted, kInk);
        d.drawString("Check a microSD is seated.", 8, kBodyTop + 24);
    } else {
        d.setTextColor(kGood, kInk);
        ui::textAt(8, kBodyTop + 10, kGood, "%u code%s written",
                   static_cast<unsigned>(savedCount_), savedCount_ == 1 ? "" : "s");
        d.setTextColor(kMuted, kInk);
        d.drawString(savePath_, 8, kBodyTop + 24);
        ui::wrapText(8, kBodyTop + 42, bd::kScreenW - 16, 10, 3, kFaint,
                     "Decoded protocol and address where we have them, and the "
                     "raw microsecond timings either way.");
    }

    ui::footer("any key   back");
    ui::endFrame();
}

bool IrLearn::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Saved) {
        view_ = View::List;
        return true;
    }

    if (ks.enter) {
        if (view_ == View::List && count_) replay();
        else if (view_ == View::Detail)    replay();
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Detail) { view_ = View::List; return true; }
                return false;

            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (selected_ + 1 < static_cast<int>(count_)) selected_++;
                return true;

            case kKeySave:
                if (count_) { saveAll(); view_ = View::Saved; }
                return true;

            case kKeyClear:
                count_    = 0;
                selected_ = 0;
                view_     = View::Listening;
                enteredMs_ = millis();
                return true;

            default:
                break;
        }
    }
    return true;
}

void IrLearn::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        pump();

        if (!handleKeys()) {
            rx_.end();     // also hands Grove Port A back to I2C
            tx_.idle();
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Listening: drawListening(); break;
                case View::List:      drawList();      break;
                case View::Detail:    drawDetail();    break;
                case View::Saved:     drawSaved();     break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
