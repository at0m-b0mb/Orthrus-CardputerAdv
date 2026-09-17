#include "rfid_keys.h"

#include <M5Cardputer.h>
#include <SD.h>

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
constexpr uint32_t kRedrawMs = 140;

constexpr int kBodyTop = 21;

constexpr char kKeyUp     = ';';
constexpr char kKeyDown   = '.';
constexpr char kKeyBack   = '`';
constexpr char kKeySave   = 's';
constexpr char kKeySweep  = 'k';

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

RfidKeys::RfidKeys() : reader_(hal::sharedReader()) {}

bool RfidKeys::begin() {
    return hal::openSharedReader();
}

// ---- the card ---------------------------------------------------------------

void RfidKeys::pollCard() {
    if (sweeping_) return;
    if (millis() - lastPollMs_ < kPollMs) return;
    lastPollMs_ = millis();

    credential::TagIdentity t;
    if (reader_.poll(t) != hal::ReaderStatus::Ok) {
        // Losing the card mid-session does not throw away the sweep: the
        // results on screen were true when they were taken, and an operator
        // who lifted the badge to read the screen should not lose them.
        if (haveCard_ && view_ == View::Card) cardLost_ = true;
        return;
    }

    cardLost_ = false;

    // A different card resets everything. Showing sector results from the last
    // badge against this one's UID would be the worst kind of wrong.
    const bool sameCard = haveCard_ && t.uidLen == tag_.uidLen &&
                          std::memcmp(t.uid, tag_.uid, t.uidLen) == 0;
    if (!sameCard) {
        tag_ = t;
        haveCard_ = true;
        for (uint8_t i = 0; i < kMaxSectors; i++) sectors_[i] = SectorResult{};
        opened_      = 0;
        sweepAt_     = 0;
        selected_    = 0;
        sectorTotal_ = hal::Rfid2::sectorCount(t.sak);
        if (sectorTotal_ > kMaxSectors) sectorTotal_ = kMaxSectors;
        view_ = View::Card;
    }

    reader_.halt();
}

void RfidKeys::startSweep() {
    if (!haveCard_ || sectorTotal_ == 0) return;
    for (uint8_t i = 0; i < kMaxSectors; i++) sectors_[i] = SectorResult{};
    opened_   = 0;
    sweepAt_  = 0;
    sweeping_ = true;
    view_     = View::Sweeping;
}

void RfidKeys::stepSweep() {
    if (!sweeping_) return;

    if (sweepAt_ >= sectorTotal_) {
        sweeping_ = false;
        view_     = View::Map;

        char uid[24];
        hexBytes(tag_.uid, tag_.uidLen, uid, sizeof(uid));
        char detail[96];
        std::snprintf(detail, sizeof(detail),
                      "mifare uid=%s sectors=%u open=%u family=%s", uid,
                      static_cast<unsigned>(sectorTotal_),
                      static_cast<unsigned>(opened_),
                      cr::familyName(tag_.family()));
        app::recorder().noteFinding(detail);
        return;
    }

    // One sector per call. A sector is up to two key types times the whole
    // published dictionary, each attempt needing a fresh anticollision, so this
    // takes a few hundred milliseconds -- long enough that doing the whole card
    // in one go would look like a hang.
    SectorResult& s = sectors_[sweepAt_];
    s.attempted = true;

    uint8_t keyIndex = 0, keyType = 0;
    if (reader_.openSector(sweepAt_, tag_, &keyIndex, &keyType)) {
        s.opened   = true;
        s.keyIndex = keyIndex;
        s.keyType  = keyType;
        opened_++;

        // Crypto1 is live only until the next reselect, so the blocks are read
        // here and now or not at all.
        const uint8_t first = hal::Rfid2::firstBlockOfSector(sweepAt_);
        for (uint8_t b = 0; b < kBlocksKept; b++) {
            if (reader_.readBlock(static_cast<uint8_t>(first + b), s.data[b]) !=
                hal::ReaderStatus::Ok)
                break;
            s.blocksRead++;
        }
        reader_.endSector();
    }

    sweepAt_++;
}

// ---- export -----------------------------------------------------------------

bool RfidKeys::saveDump() {
    saveOk_      = false;
    savedBlocks_ = 0;

    if (!app::recorder().begin() && !app::recorder().active()) return false;
    if (!SD.exists("/orthrus")) SD.mkdir("/orthrus");

    for (int i = 1; i < 1000; i++) {
        std::snprintf(dumpPath_, sizeof(dumpPath_), "/orthrus/keys-%03d.txt", i);
        if (!SD.exists(dumpPath_)) break;
        dumpPath_[0] = '\0';
    }
    if (dumpPath_[0] == '\0') return false;

    File f = SD.open(dumpPath_, FILE_WRITE);
    if (!f) return false;

    char uid[24];
    hexBytes(tag_.uid, tag_.uidLen, uid, sizeof(uid));

    f.println("# Orthrus -- Mifare Classic sector sweep");
    f.println("# Authorized testing only. Read-only: nothing on this card was");
    f.println("# written, and no key or access condition was changed.");
    f.printf("uid=%s atqa=%04x sak=%02x family=%s\n", uid,
             static_cast<unsigned>(tag_.atqa), static_cast<unsigned>(tag_.sak),
             cr::familyName(tag_.family()));
    f.printf("sectors=%u opened_with_published_key=%u\n",
             static_cast<unsigned>(sectorTotal_), static_cast<unsigned>(opened_));
    f.println();

    const cr::DefaultKey* keys = cr::defaultKeys();
    char line[72];

    for (uint8_t s = 0; s < sectorTotal_; s++) {
        const SectorResult& r = sectors_[s];
        if (!r.opened) {
            f.printf("sector %02u  no published key opened it\n",
                     static_cast<unsigned>(s));
            continue;
        }
        hexBytes(keys[r.keyIndex].key, cr::kKeyLen, line, sizeof(line));
        f.printf("sector %02u  key%c %s  (%s)\n", static_cast<unsigned>(s),
                 r.keyType == 0 ? 'A' : 'B', line, keys[r.keyIndex].origin);

        const uint8_t first = hal::Rfid2::firstBlockOfSector(s);
        for (uint8_t b = 0; b < r.blocksRead; b++) {
            hexBytes(r.data[b], 16, line, sizeof(line));
            f.printf("  block %03u  %s\n", static_cast<unsigned>(first + b), line);
            savedBlocks_++;
        }
        // Said out loud rather than implied: a 4K card's large sectors hold
        // sixteen blocks and only the first four were kept.
        if (hal::Rfid2::blocksInSector(s) > kBlocksKept)
            f.printf("  (%u further blocks in this sector were not read)\n",
                     static_cast<unsigned>(hal::Rfid2::blocksInSector(s) - kBlocksKept));
    }
    f.close();

    char detail[96];
    std::snprintf(detail, sizeof(detail), "keys dump uid=%s blocks=%u file=%s", uid,
                  static_cast<unsigned>(savedBlocks_), dumpPath_);
    app::recorder().note(evidence::RecordKind::Note, detail);

    saveOk_ = true;
    return true;
}

// ---- screens ----------------------------------------------------------------

void RfidKeys::sectorGrid(int x, int y, int maxWidth) {
    auto& d = ui::gfx();
    if (sectorTotal_ == 0) return;

    const int cols = sectorTotal_ > 16 ? 10 : 8;
    const int rows = (sectorTotal_ + cols - 1) / cols;

    constexpr int kGap = 2;
    int cell = (maxWidth - (cols - 1) * kGap) / cols;
    if (cell > 12) cell = 12;
    if (cell < 5) cell = 5;

    for (int i = 0; i < sectorTotal_; i++) {
        const int c = i % cols;
        const int r = i / cols;
        const int cx = x + c * (cell + kGap);
        const int cy = y + r * (cell + kGap);

        const SectorResult& s = sectors_[i];
        if (s.opened) {
            d.fillRect(cx, cy, cell, cell, kShine);
        } else if (s.attempted) {
            // Tried and refused: drawn, never omitted. A sector we could not
            // open is a result, not a gap.
            d.drawRect(cx, cy, cell, cell, kGood);
        } else {
            d.drawRect(cx, cy, cell, cell, kRule);
        }

        if (i == selected_ && (view_ == View::Map || view_ == View::Sector))
            d.drawRect(cx - 1, cy - 1, cell + 2, cell + 2, kText);
    }
    (void)rows;
}

void RfidKeys::drawWaiting() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Test Keys", reader_.present() ? "reader ok" : "no reader");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Present a Mifare Classic badge.", 8, kBodyTop + 8);

    ui::wrapText(8, kBodyTop + 26, bd::kScreenW - 16, 11, 4, kFaint,
                 "Every sector is tried against every published key, both key "
                 "types. Read only: nothing on the card is changed.");

    ui::footer("` back");
    ui::endFrame();
}

void RfidKeys::drawCard() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char uid[24];
    hexBytes(tag_.uid, tag_.uidLen, uid, sizeof(uid));
    ui::chrome("Test Keys", uid);

    d.setFont(kFaceData);
    ui::textAt(8, kBodyTop + 6, kText, "%s", cr::familyName(tag_.family()));
    ui::textAt(8, kBodyTop + 20, kMuted, "atqa %04x   sak %02x",
               static_cast<unsigned>(tag_.atqa), static_cast<unsigned>(tag_.sak));

    if (sectorTotal_ == 0) {
        ui::textAt(8, kBodyTop + 40, kHigh, "Not a Crypto1 card.");
        ui::wrapText(8, kBodyTop + 52, bd::kScreenW - 16, 10, 3, kFaint,
                     "Sector keys only exist on Mifare Classic. This badge uses a "
                     "different cipher and has nothing here to try.");
        ui::footer("` back");
    } else {
        ui::textAt(8, kBodyTop + 40, kMuted, "%u sectors to try",
                   static_cast<unsigned>(sectorTotal_));
        if (cardLost_) {
            ui::textAt(8, kBodyTop + 54, kHigh, "Card lifted -- hold it still.");
        } else {
            ui::textAt(8, kBodyTop + 54, kFaint, "Hold the badge on the reader.");
        }
        ui::footer("k sweep   ` back");
    }

    d.setTextDatum(top_left);
    ui::endFrame();
}

void RfidKeys::drawSweeping() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u/%u", static_cast<unsigned>(sweepAt_),
                  static_cast<unsigned>(sectorTotal_));
    ui::chrome("Sweeping", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Trying every published key.", 8, kBodyTop + 6);

    // Progress bar, because a sweep of a 4K card is the better part of a
    // minute and a still screen reads as a crash.
    const int barW = bd::kScreenW - 16;
    d.drawRect(8, kBodyTop + 22, barW, 8, kRule);
    if (sectorTotal_)
        d.fillRect(9, kBodyTop + 23, (barW - 2) * sweepAt_ / sectorTotal_, 6, kShine);

    sectorGrid(8, kBodyTop + 38, bd::kScreenW - 16);

    ui::textAt(8, bd::kScreenH - kFooterH - 12, kText, "%u open so far",
               static_cast<unsigned>(opened_));

    ui::footer("` stop");
    ui::endFrame();
}

void RfidKeys::drawMap() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u/%u open", static_cast<unsigned>(opened_),
                  static_cast<unsigned>(sectorTotal_));
    ui::chrome("Sectors", right);

    sectorGrid(8, kBodyTop + 4, bd::kScreenW - 16);

    d.setFont(kFaceData);
    const int textY = kBodyTop + 40;

    if (opened_ == 0) {
        ui::textAt(8, textY, kGood, "No published key opened it.");
        ui::wrapText(8, textY + 12, bd::kScreenW - 16, 10, 3, kMuted,
                     "This card was configured. It does not mean the keys are "
                     "strong -- only that they are not the printed ones.");
    } else if (opened_ == sectorTotal_) {
        ui::textAt(8, textY, kCritical, "Every sector is factory-keyed.");
        ui::wrapText(8, textY + 12, bd::kScreenW - 16, 10, 3, kMuted,
                     "The whole badge is readable and writable by anyone with a "
                     "five pound reader. It was never configured.");
    } else {
        ui::textAt(8, textY, kHigh, "%u of %u sectors are factory-keyed.",
                   static_cast<unsigned>(opened_),
                   static_cast<unsigned>(sectorTotal_));
        ui::wrapText(8, textY + 12, bd::kScreenW - 16, 10, 3, kMuted,
                     "Partly configured. Whatever lives in the open sectors is "
                     "readable by anyone.");
    }

    d.setTextDatum(top_left);
    ui::footer("; . sector  enter open  s save  ` back");
    ui::endFrame();
}

void RfidKeys::drawSector() {
    if (selected_ < 0 || selected_ >= sectorTotal_) {
        view_ = View::Map;
        return;
    }

    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "sector %u", static_cast<unsigned>(selected_));
    ui::chrome("Sector", right);

    const SectorResult& s = sectors_[selected_];
    d.setFont(kFaceData);

    if (!s.opened) {
        ui::textAt(8, kBodyTop + 8, kGood, "No published key opened it.");
        ui::wrapText(8, kBodyTop + 24, bd::kScreenW - 16, 11, 4, kMuted,
                     "Orthrus does not implement nested or darkside key recovery. "
                     "The honest answer is that we could not open it, not that the "
                     "key is strong.");
        ui::footer("; . sector   ` back");
        ui::endFrame();
        return;
    }

    const cr::DefaultKey* keys = cr::defaultKeys();
    char hex[16];
    hexBytes(keys[s.keyIndex].key, cr::kKeyLen, hex, sizeof(hex));
    ui::textAt(8, kBodyTop + 5, kShine, "key%c %s", s.keyType == 0 ? 'A' : 'B', hex);
    ui::textAt(8, kBodyTop + 16, kFaint, "%.34s", keys[s.keyIndex].origin);

    d.drawFastHLine(6, kBodyTop + 24, bd::kScreenW - 12, kRule);

    const uint8_t first = hal::Rfid2::firstBlockOfSector(selected_);
    int y = kBodyTop + 32;
    for (uint8_t b = 0; b < s.blocksRead && b < kBlocksKept; b++) {
        // Sixteen bytes will not fit on a 240 px line in this face, so each
        // block shows its first eight and says so by ending in a rule, not by
        // pretending the rest is not there.
        char half[20];
        hexBytes(s.data[b], 8, half, sizeof(half));
        ui::textAt(8, y, kMuted, "%03u", static_cast<unsigned>(first + b));
        ui::textAt(34, y, kText, "%s..", half);
        y += 11;
    }
    if (s.blocksRead == 0)
        ui::textAt(8, y, kFaint, "opened, but no block read back");

    d.setTextDatum(top_left);
    ui::footer("; . sector   s save   ` back");
    ui::endFrame();
}

void RfidKeys::drawSaved() {
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
        ui::textAt(8, kBodyTop + 10, kGood, "%u blocks written",
                   static_cast<unsigned>(savedBlocks_));
        d.setTextColor(kMuted, kInk);
        d.drawString(dumpPath_, 8, kBodyTop + 24);
        ui::wrapText(8, kBodyTop + 42, bd::kScreenW - 16, 10, 3, kFaint,
                     "Keys, origins and the blocks behind them. The header says "
                     "read-only, because it was.");
    }

    ui::footer("any key   back");
    ui::endFrame();
}

bool RfidKeys::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::Saved) {
        view_ = View::Map;
        return true;
    }

    if (ks.enter) {
        if (view_ == View::Card && sectorTotal_) startSweep();
        else if (view_ == View::Map)             view_ = View::Sector;
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Sweeping) {
                    // Stopping leaves what was already found on screen. A
                    // partial sweep is still a result, as long as the map shows
                    // which sectors were never tried.
                    sweeping_ = false;
                    view_     = View::Map;
                    return true;
                }
                if (view_ == View::Sector) { view_ = View::Map; return true; }
                if (view_ == View::Map)    { view_ = View::Card; return true; }
                return false;

            case kKeySweep:
                if (view_ == View::Card && sectorTotal_) startSweep();
                return true;

            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (selected_ + 1 < sectorTotal_) selected_++;
                return true;

            case kKeySave:
                if (haveCard_ && sweepAt_ > 0) {
                    saveDump();
                    view_ = View::Saved;
                }
                return true;

            default:
                break;
        }
    }
    return true;
}

void RfidKeys::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        pollCard();
        stepSweep();

        if (!handleKeys()) {
            reader_.antennaOff();   // ~26 mA with the field live
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Waiting:  drawWaiting();  break;
                case View::Card:     drawCard();     break;
                case View::Sweeping: drawSweeping(); break;
                case View::Map:      drawMap();      break;
                case View::Sector:   drawSector();   break;
                case View::Saved:    drawSaved();    break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
