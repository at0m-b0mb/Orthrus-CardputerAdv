// Payload: the USB HID surface.
//
// The Cardputer presents itself to a host as a keyboard and types a script the
// operator wrote. That is a real capability on an authorized engagement and it
// is also the one surface here that touches somebody else's machine directly,
// so the shape of it matters:
//
//   - Payloads come from the operator's own SD card. None are bundled. A tool
//     that ships ready-made attack scripts is a tool that gets used without
//     anyone reading them.
//   - Nothing ever runs on boot, on plug-in, or on entering the screen.
//   - The script is PARSED AND VALIDATED before it can be armed, so an
//     unrecognised line is found in your hand rather than in front of a target.
//   - Arming and firing are separate keys, and the screen says what is armed.
//   - Any key aborts mid-run, and every run is written to the evidence log.
//
// None of that is friction for its own sake. It is the difference between an
// instrument and an accident.

#pragma once

#include <cstdint>

#include "ducky/script.h"
#include "hal/hid.h"

namespace orthrus::modules {

class UsbBadUsb {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Preview, Running, Done, NoHid };

    static constexpr uint8_t kMaxFiles   = 16;
    static constexpr uint8_t kNameLen    = 32;
    static constexpr uint16_t kMaxLineLen = 320;

    void scanFiles();
    void validate();      // parse the whole script without typing anything
    void execute();       // type it
    void drawList();
    void drawPreview();
    void drawDone();
    void drawNoHid();
    bool handleKeys();

    hal::Hid& hid_ = hal::sharedHid();

    char    files_[kMaxFiles][kNameLen] = {{0}};
    uint8_t fileCount_ = 0;
    int     selected_  = 0;
    int     scroll_    = 0;

    // Validation results for the selected file.
    uint16_t lineCount_    = 0;
    uint16_t actionCount_  = 0;
    uint16_t unknownCount_ = 0;
    uint16_t firstBadLine_ = 0;
    char     firstBadWord_[ducky::kMaxWordLen] = {0};
    bool     validated_    = false;
    bool     armed_        = false;

    // Execution results.
    uint16_t ranLines_ = 0;
    uint32_t sentKeys_ = 0;
    bool     aborted_  = false;

    View     view_       = View::List;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
