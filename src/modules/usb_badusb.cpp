#include "usb_badusb.h"

#include <M5Cardputer.h>
#include <SD.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"
#include "hal/lora_radio.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace dk = orthrus::ducky;

namespace {

constexpr int  kBodyTop = 21;
constexpr int  kRowH    = 14;
constexpr int  kRows    = 6;
constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';

constexpr const char* kPayloadDir = "/orthrus/payloads";

// Default gap between keystrokes. Faster than this and some hosts, especially
// remote desktop sessions and virtual machines, drop characters.
constexpr uint16_t kDefaultKeyDelayMs = 12;

}  // namespace

bool UsbBadUsb::begin() {
    if (!hal::hidSupportedInBuild()) {
        view_ = View::NoHid;
        return true;
    }
    hid_.begin();  // already up from setup(); this is a no-op
    SD.begin(bd::kSdCs, hal::sharedSpi(), 20000000);
    scanFiles();
    return true;
}

void UsbBadUsb::scanFiles() {
    fileCount_ = 0;
    File dir = SD.open(kPayloadDir);
    if (!dir || !dir.isDirectory()) {
        if (dir) dir.close();
        return;
    }

    for (File f = dir.openNextFile(); f && fileCount_ < kMaxFiles;
         f = dir.openNextFile()) {
        if (f.isDirectory()) { f.close(); continue; }

        const char* name = f.name();
        // Strip any leading path the driver hands back, so the list shows a
        // filename rather than a path that will not fit on the panel.
        const char* slash = std::strrchr(name, '/');
        if (slash) name = slash + 1;

        std::snprintf(files_[fileCount_], kNameLen, "%s", name);
        fileCount_++;
        f.close();
    }
    dir.close();
}

void UsbBadUsb::validate() {
    lineCount_ = actionCount_ = unknownCount_ = firstBadLine_ = 0;
    firstBadWord_[0] = '\0';
    validated_ = false;
    armed_     = false;

    if (selected_ < 0 || selected_ >= static_cast<int>(fileCount_)) return;

    char path[80];
    std::snprintf(path, sizeof(path), "%s/%s", kPayloadDir, files_[selected_]);
    File f = SD.open(path, FILE_READ);
    if (!f) return;

    char line[kMaxLineLen];
    while (f.available()) {
        const size_t n = f.readBytesUntil('\n', line, sizeof(line) - 1);
        line[n] = '\0';
        lineCount_++;

        dk::ParsedLine p;
        dk::parseLine(line, p);

        if (p.kind == dk::LineKind::Unknown) {
            unknownCount_++;
            if (firstBadLine_ == 0) {
                firstBadLine_ = lineCount_;
                std::snprintf(firstBadWord_, sizeof(firstBadWord_), "%s",
                              p.unknownWord);
            }
        } else if (!dk::isNoop(p.kind)) {
            actionCount_++;
        }
    }
    f.close();
    validated_ = true;
}

void UsbBadUsb::execute() {
    ranLines_ = 0;
    sentKeys_ = 0;
    aborted_  = false;

    char path[80];
    std::snprintf(path, sizeof(path), "%s/%s", kPayloadDir, files_[selected_]);
    File f = SD.open(path, FILE_READ);
    if (!f) { view_ = View::Done; return; }

    uint16_t defaultDelay = 0;
    char     line[kMaxLineLen];
    char     previous[kMaxLineLen] = {0};

    // Paint before blocking. The operator is standing over someone else's
    // machine and needs to see that this is running and how to stop it.
    ui::beginFrame();
    ui::chrome("BadUSB", "RUNNING");
    {
        auto& d = ui::gfx();
        d.setFont(kFaceIdentity);
        d.setTextDatum(middle_center);
        d.setTextColor(kShine, kInk);
        d.drawString("TYPING", bd::kScreenW / 2, 54);
        d.setFont(kFaceData);
        d.setTextColor(kMuted, kInk);
        d.drawString(files_[selected_], bd::kScreenW / 2, 78);
        d.setTextDatum(top_left);
    }
    ui::footer("any key aborts");
    ui::endFrame();

    const uint32_t startedAt = millis();

    while (f.available()) {
        // Any key aborts. The operator is standing over a machine that is not
        // theirs and must be able to stop it instantly.
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            aborted_ = true;
            break;
        }

        const size_t n = f.readBytesUntil('\n', line, sizeof(line) - 1);
        line[n] = '\0';

        dk::ParsedLine p;
        dk::parseLine(line, p);

        // REPEAT re-runs the PREVIOUS line, so it has to be resolved against a
        // copy rather than the buffer we are about to overwrite.
        uint32_t repeats = 1;
        if (p.kind == dk::LineKind::Repeat) {
            repeats = p.number;
            dk::parseLine(previous, p);
            if (repeats > 500) repeats = 500;  // a typo should not run forever
        } else {
            std::snprintf(previous, sizeof(previous), "%s", line);
        }

        for (uint32_t r = 0; r < repeats && !aborted_; r++) {
            switch (p.kind) {
                case dk::LineKind::Delay:
                    delay(p.number > 60000 ? 60000 : p.number);
                    break;
                case dk::LineKind::DefaultDelay:
                    defaultDelay = static_cast<uint16_t>(
                        p.number > 1000 ? 1000 : p.number);
                    break;
                case dk::LineKind::String:
                case dk::LineKind::StringLn:
                    sentKeys_ += hid_.type(p.text, p.textLen, kDefaultKeyDelayMs);
                    if (p.kind == dk::LineKind::StringLn) {
                        if (hid_.chord(0, dk::kKeyEnter)) sentKeys_++;
                    }
                    break;
                case dk::LineKind::Keys:
                    // Counted only when the host actually took it. Incrementing
                    // regardless is how a device ends up reporting "200 keys
                    // sent" for a payload that typed nothing.
                    if (hid_.chord(p.modifiers, p.keycode)) sentKeys_++;
                    break;
                default:
                    break;  // comments, blanks and unknowns do nothing
            }
            if (defaultDelay) delay(defaultDelay);
        }

        ranLines_++;
    }

    f.close();
    // Never leave a modifier held on the host, whatever happened above.
    hid_.releaseAll();

    droppedKeys_ = hid_.keysDropped();

    char detail[96];
    std::snprintf(detail, sizeof(detail),
                  "hid=%.24s lines=%u keys=%lu drop=%lu %s", files_[selected_],
                  static_cast<unsigned>(ranLines_),
                  static_cast<unsigned long>(sentKeys_),
                  static_cast<unsigned long>(droppedKeys_),
                  aborted_ ? "aborted" : "complete");
    app::recorder().noteFinding(detail);

    armed_ = false;
    view_  = View::Done;
}

void UsbBadUsb::drawNoHid() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("BadUSB", "unavailable");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    d.drawString("HID not in this build.", 8, kBodyTop + 12);
    d.setTextColor(kMuted, kInk);
    ui::wrapText(8, kBodyTop + 30, bd::kScreenW - 16, 11, 4, kMuted,
                 "This firmware uses the hardware USB-JTAG, which cannot "
                 "present a keyboard. Build with ARDUINO_USB_MODE=0.");
    ui::footer("` back");
    ui::endFrame();
}

void UsbBadUsb::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u file%s",
                  static_cast<unsigned>(fileCount_), fileCount_ == 1 ? "" : "s");
    ui::chrome("BadUSB", right);

    if (fileCount_ == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString("No payloads on the card.", 8, kBodyTop + 10);
        d.setTextColor(kFaint, kInk);
        ui::wrapText(8, kBodyTop + 28, bd::kScreenW - 16, 11, 3, kFaint,
                     "Put DuckyScript .txt files in /orthrus/payloads. None "
                     "are shipped: a payload should be one you have read.");
        ui::footer("r rescan   ` back");
        ui::endFrame();
        return;
    }

    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kRows) scroll_ = selected_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int idx = scroll_ + i;
        if (idx >= static_cast<int>(fileCount_)) break;

        const int y   = kBodyTop + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kRowH, sel);

        d.setFont(kFaceData);
        d.setTextDatum(middle_left);
        d.setTextColor(kText, sel ? kSurface : kInk);
        d.drawString(files_[idx], 8, mid);
    }

    d.setTextDatum(top_left);
    ui::footer("enter check   ; . move   r rescan   ` back");
    ui::endFrame();
}

void UsbBadUsb::drawPreview() {
    ui::beginFrame();
    auto& d = ui::gfx();

    ui::chrome(armed_ ? "ARMED" : "Check", files_[selected_]);

    d.setFont(kFaceData);
    int y = kBodyTop + 6;

    ui::textAt(8, y, kMuted, "lines");
    ui::textRight(bd::kScreenW - 8, y, kText, "%u", static_cast<unsigned>(lineCount_));
    y += 13;
    ui::textAt(8, y, kMuted, "actions");
    ui::textRight(bd::kScreenW - 8, y, kText, "%u", static_cast<unsigned>(actionCount_));
    y += 13;

    ui::textAt(8, y, kMuted, "not understood");
    ui::textRight(bd::kScreenW - 8, y, unknownCount_ ? kCritical : kGood, "%u",
                  static_cast<unsigned>(unknownCount_));
    y += 15;

    if (unknownCount_ > 0) {
        // Naming the line and the word is the difference between a fixable
        // problem and a shrug, and this is the moment to find it -- before the
        // device is anywhere near a target.
        ui::textAt(8, y, kCritical, "line %u: %s",
                   static_cast<unsigned>(firstBadLine_), firstBadWord_);
        y += 13;
        ui::textAt(8, y, kFaint, "Those lines will be skipped.");
    } else if (armed_) {
        d.setFont(kFaceIdentity);
        d.setTextDatum(middle_center);
        d.setTextColor(kShine, kInk);
        d.drawString("ENTER TO FIRE", bd::kScreenW / 2, y + 12);
        d.setTextDatum(top_left);
        d.setFont(kFaceData);
        ui::textAt(8, y + 30, kFaint, hid_.hostReady()
               ? "USB settled. A host never confirms it is listening."
               : "Give USB a moment to enumerate.");
    } else {
        ui::textAt(8, y, kFaint, "Nothing has been typed yet.");
    }

    ui::footer(armed_ ? "enter FIRE   ` disarm"
                      : "a arm   ` back");
    ui::endFrame();
}

void UsbBadUsb::drawDone() {
    ui::beginFrame();
    ui::chrome(aborted_ ? "Aborted" : "Finished", files_[selected_]);

    auto& d = ui::gfx();
    d.setFont(kFaceData);
    int y = kBodyTop + 10;

    ui::textAt(8, y, kMuted, "lines run");
    ui::textRight(bd::kScreenW - 8, y, kText, "%u", static_cast<unsigned>(ranLines_));
    y += 14;
    ui::textAt(8, y, kMuted, "keys taken");
    ui::textRight(bd::kScreenW - 8, y, kText, "%lu",
                  static_cast<unsigned long>(sentKeys_));
    y += 14;

    // Shown whenever it is non-zero, because a payload that half-typed is the
    // one thing an operator must not walk away believing worked.
    if (droppedKeys_) {
        ui::textAt(8, y, kCritical, "dropped");
        ui::textRight(bd::kScreenW - 8, y, kCritical, "%lu",
                      static_cast<unsigned long>(droppedKeys_));
        y += 14;
    } else {
        y += 4;
    }

    if (droppedKeys_) {
        ui::textAt(8, y, kCritical, "The host stopped taking keys.");
        y += 13;
        ui::textAt(8, y, kFaint, "Typed output is incomplete.");
    } else {
        ui::textAt(8, y, aborted_ ? kHigh : kGood,
                   aborted_ ? "Stopped by keypress." : "Completed.");
        y += 13;
        ui::textAt(8, y, kFaint, "Written to the engagement log.");
    }

    ui::footer("any key   back");
    ui::endFrame();
}

bool UsbBadUsb::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    if (view_ == View::NoHid) return false;

    if (view_ == View::Done) {
        view_ = View::List;
        return true;
    }

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (ks.enter) {
        if (view_ == View::List && fileCount_) {
            validate();
            view_ = View::Preview;
        } else if (view_ == View::Preview && armed_) {
            view_ = View::Running;
            execute();
        }
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Preview) {
                    // Backing out always disarms. Leaving a screen armed is how
                    // something fires when nobody meant it to.
                    armed_ = false;
                    view_  = View::List;
                    return true;
                }
                return false;

            case 'a':
                if (view_ == View::Preview && validated_) armed_ = true;
                return true;

            case 'r':
                if (view_ == View::List) { scanFiles(); selected_ = 0; }
                return true;

            case kKeyUp:
                if (view_ == View::List && selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (view_ == View::List && selected_ + 1 < static_cast<int>(fileCount_))
                    selected_++;
                return true;

            default:
                break;
        }
    }
    return true;
}

void UsbBadUsb::run() {
    for (;;) {
        M5Cardputer.update();
        if (!handleKeys()) {
            hid_.releaseAll();
            return;
        }

        if (millis() - lastDrawMs_ >= 150) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::List:    drawList();    break;
                case View::Preview: drawPreview(); break;
                case View::Done:    drawDone();    break;
                case View::NoHid:   drawNoHid();   break;
                case View::Running: break;  // execute() owns the screen
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
