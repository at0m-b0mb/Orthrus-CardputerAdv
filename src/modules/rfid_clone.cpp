#include "rfid_clone.h"

#include <M5Cardputer.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "credential/defaults.h"
#include "credential/grade.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace cr = orthrus::credential;

namespace {

constexpr uint32_t kPollMs   = 250;
constexpr uint32_t kRedrawMs = 150;

constexpr int kBodyTop = 21;

constexpr char kKeyBack  = '`';
constexpr char kKeyArm   = 'a';
constexpr char kKeyRead  = 'r';

void hexBytes(const uint8_t* p, size_t n, char* out, size_t cap) {
    static const char kHex[] = "0123456789abcdef";
    size_t w = 0;
    for (size_t i = 0; i < n && w + 3 < cap; i++) {
        out[w++] = kHex[(p[i] >> 4) & 0x0F];
        out[w++] = kHex[p[i] & 0x0F];
    }
    out[w] = '\0';
}

}  // namespace

RfidClone::RfidClone() : reader_(hal::sharedReader()) {}

bool RfidClone::begin() {
    view_       = View::WaitSource;
    haveSource_ = false;
    blankSeen_  = false;
    armed_      = false;
    return hal::openSharedReader();
}

// ---- reading the source ------------------------------------------------------

void RfidClone::pollSource() {
    if (view_ != View::WaitSource) return;
    if (millis() - lastPollMs_ < kPollMs) return;
    lastPollMs_ = millis();

    credential::TagIdentity t;
    if (reader_.poll(t) != hal::ReaderStatus::Ok) return;

    source_     = t;
    haveSource_ = true;
    sectorTotal_ = hal::Rfid2::sectorCount(t.sak);
    if (sectorTotal_ > kMaxSectors) sectorTotal_ = kMaxSectors;

    for (uint8_t i = 0; i < kMaxSectors; i++) sectors_[i] = SectorCopy{};
    readAt_      = 0;
    sectorsRead_ = 0;
    reading_     = sectorTotal_ > 0;
    view_        = reading_ ? View::Reading : View::Source;
    reader_.halt();
}

void RfidClone::stepRead() {
    if (!reading_) return;

    if (readAt_ >= sectorTotal_) {
        reading_ = false;
        view_    = View::Source;
        return;
    }

    SectorCopy& s = sectors_[readAt_];
    uint8_t keyIndex = 0, keyType = 0;
    if (reader_.openSector(readAt_, source_, &keyIndex, &keyType)) {
        const uint8_t first = hal::Rfid2::firstBlockOfSector(readAt_);
        uint8_t got = 0;
        for (uint8_t b = 0; b < kBlocksPerSector; b++) {
            if (reader_.readBlock(static_cast<uint8_t>(first + b), s.data[b]) !=
                hal::ReaderStatus::Ok)
                break;
            got++;
        }
        reader_.endSector();
        if (got == kBlocksPerSector) {
            s.read = true;
            sectorsRead_++;
        }
    }
    readAt_++;
}

// ---- the destination ---------------------------------------------------------

void RfidClone::pollBlank() {
    if (view_ != View::WaitBlank) return;
    if (millis() - lastPollMs_ < kPollMs) return;
    lastPollMs_ = millis();

    credential::TagIdentity t;
    if (reader_.poll(t) != hal::ReaderStatus::Ok) {
        blankSeen_ = false;
        return;
    }

    // The same card is almost certainly the operator forgetting to swap it.
    // Saying so beats silently refusing to arm.
    blank_     = t;
    blankSeen_ = true;

    // The probe that decides everything: a Gen1a blank answers the backdoor, a
    // real badge ignores it. Harmless either way, and it happens before
    // anything can be armed.
    blankIsMagic_ = reader_.magicUnlock();
    reader_.endSector();
}

void RfidClone::stepWrite() {
    if (!writing_) return;

    if (writeAt_ >= sectorTotal_) {
        writing_ = false;
        view_    = View::Result;

        char uid[24];
        hexBytes(source_.uid, source_.uidLen, uid, sizeof(uid));
        char detail[96];
        std::snprintf(detail, sizeof(detail),
                      "clone uid=%s blocks=%u failed=%u uid_block=%s", uid,
                      static_cast<unsigned>(blocksWritten_),
                      static_cast<unsigned>(blocksFailed_),
                      uidWritten_ ? "yes" : "no");
        app::recorder().noteDevice(detail);
        return;
    }

    const SectorCopy& s = sectors_[writeAt_];
    if (!s.read) {
        writeAt_++;
        return;
    }

    // Unlock once per sector: a reselect drops the backdoor state, and every
    // failed write ends with one.
    const bool magic = reader_.magicUnlock();
    const uint8_t first = hal::Rfid2::firstBlockOfSector(writeAt_);

    for (uint8_t b = 0; b < kBlocksPerSector; b++) {
        const uint8_t block = static_cast<uint8_t>(first + b);

        // The sector trailer carries the keys and access bits. Writing a wrong
        // one locks the sector permanently -- on a blank that is merely
        // annoying, but it is also the block most likely to be rejected, so it
        // is skipped and the card keeps its own factory trailer.
        if (b == kBlocksPerSector - 1) continue;

        const bool isManufacturer = (block == 0);
        if (isManufacturer && !magic) {
            // A Gen2 card takes block 0 through a normal authenticated write;
            // a card that is neither will refuse, which is the safe outcome.
            blocksFailed_++;
            continue;
        }

        if (reader_.writeBlock(block, s.data[b], isManufacturer) ==
            hal::ReaderStatus::Ok) {
            blocksWritten_++;
            if (isManufacturer) uidWritten_ = true;
        } else {
            blocksFailed_++;
        }
    }
    reader_.endSector();
    writeAt_++;
}

// ---- screens -----------------------------------------------------------------

void RfidClone::drawWaitSource() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Clone", reader_.present() ? "step 1 of 2" : "no reader");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kText, kInk);
    d.drawString("Present the badge to copy.", 8, kBodyTop + 8);

    ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 4, kFaint,
                 "It is only read. Nothing is written to it, and it leaves the "
                 "reader exactly as it arrived.");

    ui::footer("` back");
    ui::endFrame();
}

void RfidClone::drawReading() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u/%u", static_cast<unsigned>(readAt_),
                  static_cast<unsigned>(sectorTotal_));
    ui::chrome("Reading", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Opening what the published keys open.", 8, kBodyTop + 8);

    const int barW = bd::kScreenW - 16;
    d.drawRect(8, kBodyTop + 26, barW, 8, kRule);
    if (sectorTotal_)
        d.fillRect(9, kBodyTop + 27, (barW - 2) * readAt_ / sectorTotal_, 6, kShine);

    ui::textAt(8, kBodyTop + 46, kText, "%u sectors copied",
               static_cast<unsigned>(sectorsRead_));

    ui::footer("hold the card still");
    ui::endFrame();
}

void RfidClone::drawSource() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char uid[24];
    hexBytes(source_.uid, source_.uidLen, uid, sizeof(uid));
    ui::chrome("Source", uid);

    d.setFont(kFaceData);
    ui::textAt(8, kBodyTop + 5, kText, "%s", cr::familyName(source_.family()));

    if (sectorTotal_ == 0) {
        ui::textAt(8, kBodyTop + 20, kHigh, "Not a Mifare Classic card.");
        ui::wrapText(8, kBodyTop + 34, bd::kScreenW - 16, 10, 4, kFaint,
                     "Only Crypto1 cards can be copied onto the blanks this "
                     "device can write. A DESFire or NTAG cannot.");
        ui::footer("r again   ` back");
        ui::endFrame();
        return;
    }

    const uint16_t colour = sectorsRead_ == sectorTotal_ ? kGood
                            : sectorsRead_ ? kMedium : kCritical;
    ui::textAt(8, kBodyTop + 20, colour, "%u of %u sectors readable",
               static_cast<unsigned>(sectorsRead_),
               static_cast<unsigned>(sectorTotal_));

    const char* note;
    if (sectorsRead_ == 0) {
        note = "No published key opened anything. Only the UID can be copied, "
               "which is enough for readers that check nothing else.";
    } else if (sectorsRead_ == sectorTotal_) {
        note = "The whole card came across. A copy will be indistinguishable "
               "from the original to any reader.";
    } else {
        note = "A partial copy. The sectors that stayed shut will be whatever "
               "the blank already had in them, and the screen will say so.";
    }
    ui::wrapText(8, kBodyTop + 34, bd::kScreenW - 16, 10, 4, kMuted, note);

    d.setTextDatum(top_left);
    ui::footer("enter continue   r re-read   ` back");
    ui::endFrame();
}

void RfidClone::drawWaitBlank() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Clone", "step 2 of 2");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (!blankSeen_) {
        d.setTextColor(kText, kInk);
        d.drawString("Now present the blank.", 8, kBodyTop + 8);
        ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 4, kFaint,
                     "It must be a magic card -- one sold with a writable "
                     "manufacturer block. A normal card will be refused.");
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    const bool sameCard = blank_.uidLen == source_.uidLen &&
                          std::memcmp(blank_.uid, source_.uid, blank_.uidLen) == 0;

    char uid[24];
    hexBytes(blank_.uid, blank_.uidLen, uid, sizeof(uid));
    ui::textAt(8, kBodyTop + 5, kMuted, "%s", uid);

    if (sameCard) {
        ui::textAt(8, kBodyTop + 22, kHigh, "That is the source card.");
        ui::wrapText(8, kBodyTop + 36, bd::kScreenW - 16, 10, 3, kFaint,
                     "Swap it for the blank. Nothing will be written to the "
                     "badge you are copying.");
        ui::footer("` back");
    } else if (blankIsMagic_) {
        ui::textAt(8, kBodyTop + 22, kGood, "Magic card. Writable.");
        ui::wrapText(8, kBodyTop + 36, bd::kScreenW - 16, 10, 3, kMuted,
                     "It answered the backdoor, so its manufacturer block can be "
                     "rewritten with the source UID.");
        if (armed_) {
            ui::textAt(8, bd::kScreenH - kFooterH - 11, kCritical,
                       "ARMED -- enter writes");
            ui::footer("enter write   a disarm   ` back");
        } else {
            ui::footer("a arm   ` back");
        }
    } else {
        ui::textAt(8, kBodyTop + 22, kCritical, "Not a magic card.");
        ui::wrapText(8, kBodyTop + 36, bd::kScreenW - 16, 10, 4, kFaint,
                     "It ignored the backdoor, which is what a real badge does. "
                     "Refusing to write to it is the point.");
        ui::footer("` back");
    }

    d.setTextDatum(top_left);
    ui::endFrame();
}

void RfidClone::drawWriting() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u/%u", static_cast<unsigned>(writeAt_),
                  static_cast<unsigned>(sectorTotal_));
    ui::chrome("Writing", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    d.drawString("Writing to the blank.", 8, kBodyTop + 8);

    const int barW = bd::kScreenW - 16;
    d.drawRect(8, kBodyTop + 26, barW, 8, kRule);
    if (sectorTotal_)
        d.fillRect(9, kBodyTop + 27, (barW - 2) * writeAt_ / sectorTotal_, 6,
                   kCritical);

    ui::textAt(8, kBodyTop + 46, kText, "%u blocks written",
               static_cast<unsigned>(blocksWritten_));

    ui::footer("hold the card still");
    ui::endFrame();
}

void RfidClone::drawResult() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Result");

    d.setFont(kFaceUi);
    d.setTextDatum(middle_left);

    const bool good = uidWritten_ && blocksFailed_ == 0;
    d.setTextColor(good ? kGood : (uidWritten_ ? kMedium : kCritical), kInk);
    d.drawString(uidWritten_ ? (good ? "Cloned" : "Partly cloned") : "Failed", 8,
                 kBodyTop + 12);

    d.setFont(kFaceData);
    ui::textAt(8, kBodyTop + 30, kFaint, "%u written   %u refused",
               static_cast<unsigned>(blocksWritten_),
               static_cast<unsigned>(blocksFailed_));

    const char* body;
    if (!uidWritten_) {
        body = "The manufacturer block would not take the UID, so this card "
               "will not answer as the original. Nothing useful was made.";
    } else if (good) {
        body = "The copy carries the source UID and every sector that could be "
               "read. Test it against the real reader.";
    } else {
        body = "The UID went across but some sectors did not. It will pass a "
               "reader that checks only the UID, and fail one that reads data.";
    }
    ui::wrapText(8, kBodyTop + 44, bd::kScreenW - 16, 10, 4, kMuted, body);

    d.setTextDatum(top_left);
    ui::footer("any key   back");
    ui::endFrame();
}

bool RfidClone::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Result) {
        view_       = View::WaitSource;
        haveSource_ = false;
        blankSeen_  = false;
        armed_      = false;
        blocksWritten_ = blocksFailed_ = 0;
        uidWritten_ = false;
        return true;
    }
    if (view_ == View::Reading || view_ == View::Writing) return true;

    if (ks.enter) {
        if (view_ == View::Source && sectorTotal_) {
            view_      = View::WaitBlank;
            blankSeen_ = false;
            armed_     = false;
        } else if (view_ == View::WaitBlank && armed_ && blankIsMagic_) {
            view_    = View::Writing;
            writing_ = true;
            writeAt_ = 0;
            blocksWritten_ = blocksFailed_ = 0;
            uidWritten_ = false;
        }
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::WaitBlank) { view_ = View::Source; armed_ = false; return true; }
                if (view_ == View::Source)    { view_ = View::WaitSource; return true; }
                return false;

            case kKeyArm:
                if (view_ == View::WaitBlank && blankIsMagic_) armed_ = !armed_;
                return true;

            case kKeyRead:
                if (view_ == View::Source) {
                    view_       = View::WaitSource;
                    haveSource_ = false;
                }
                return true;

            default:
                break;
        }
    }
    return true;
}

void RfidClone::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        pollSource();
        stepRead();
        pollBlank();
        stepWrite();

        if (!handleKeys()) {
            reader_.antennaOff();
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::WaitSource: drawWaitSource(); break;
                case View::Reading:    drawReading();    break;
                case View::Source:     drawSource();     break;
                case View::WaitBlank:  drawWaitBlank();  break;
                case View::Writing:    drawWriting();    break;
                case View::Result:     drawResult();     break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
