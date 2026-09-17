#include "sys_files.h"

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

namespace {

constexpr uint32_t kRedrawMs = 180;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';

// Bytes per line in the hex view, chosen so a line fits the 240 px panel in the
// 6 px data face: 8 bytes is 24 characters of hex plus an offset.
constexpr int kHexPerLine = 8;

void humanSize(uint32_t bytes, char* out, size_t cap) {
    if (bytes >= 1024u * 1024u)
        std::snprintf(out, cap, "%.1fM", bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024u)
        std::snprintf(out, cap, "%luK", static_cast<unsigned long>(bytes / 1024));
    else
        std::snprintf(out, cap, "%luB", static_cast<unsigned long>(bytes));
}

}  // namespace

bool SysFiles::begin() {
    // The card may never have been mounted this boot -- the recorder opens
    // lazily and a session with no findings never touches it.
    hal::beginSharedSpi();
    if (!app::recorder().active() && !app::recorder().attempted())
        app::recorder().begin();

    std::snprintf(path_, sizeof(path_), "/");
    scan();
    return true;
}

bool SysFiles::looksTextual(const char* name) {
    // Decided by extension rather than by sniffing the bytes. Every text format
    // this device writes is one it chose, so the list is exact rather than a
    // heuristic that occasionally renders a packet capture as mojibake.
    static const char* kTextExt[] = {".csv", ".txt", ".22000", ".kml", ".log",
                                     ".json", ".md"};
    const char* dot = std::strrchr(name, '.');
    if (dot == nullptr) return false;
    for (const char* ext : kTextExt) {
        if (strcasecmp(dot, ext) == 0) return true;
    }
    return false;
}

void SysFiles::scan() {
    count_     = 0;
    selected_  = 0;
    scroll_    = 0;
    truncated_ = false;

    File dir = SD.open(path_);
    if (!dir || !dir.isDirectory()) {
        if (dir) dir.close();
        view_ = View::NoCard;
        return;
    }

    for (;;) {
        File f = dir.openNextFile();
        if (!f) break;

        if (count_ >= kMaxEntries) {
            // Said out loud rather than silently showing the first forty: a
            // capture that is on the card but not on this list would look lost.
            truncated_ = true;
            f.close();
            break;
        }

        Entry e;
        const char* full = f.name();
        // Some cores return a full path from openNextFile and some a bare name.
        // Taking the part after the last slash is right for both.
        const char* slash = std::strrchr(full, '/');
        std::snprintf(e.name, kNameLen, "%s", slash ? slash + 1 : full);
        e.isDir = f.isDirectory();
        e.size  = e.isDir ? 0 : static_cast<uint32_t>(f.size());
        f.close();

        if (e.name[0] == '\0') continue;
        entries_[count_++] = e;
    }
    dir.close();

    // Directories first, then by name. A flat alphabetical list buries
    // /orthrus among whatever else the card is carrying.
    for (uint8_t i = 1; i < count_; i++) {
        Entry key = entries_[i];
        int j = static_cast<int>(i) - 1;
        while (j >= 0) {
            const Entry& a = entries_[j];
            const bool after = (a.isDir == key.isDir)
                                   ? (strcasecmp(a.name, key.name) > 0)
                                   : (!a.isDir && key.isDir);
            if (!after) break;
            entries_[j + 1] = entries_[j];
            j--;
        }
        entries_[j + 1] = key;
    }

    view_ = View::List;
}

bool SysFiles::joinPath(const char* dir, const char* name, char* out, size_t cap) {
    const bool atRoot = (std::strcmp(dir, "/") == 0);
    // Measured BEFORE building it. A path that does not fit would otherwise be
    // silently clipped -- and a clipped path is not a shorter path, it is a
    // different file, which is a much worse thing to hand to SD.open().
    const size_t need = (atRoot ? 1 : std::strlen(dir) + 1) + std::strlen(name);
    if (need + 1 > cap) return false;

    if (atRoot) std::snprintf(out, cap, "/%s", name);
    else        std::snprintf(out, cap, "%s/%s", dir, name);
    return true;
}

void SysFiles::descend(const Entry& e) {
    char next[kPathLen];
    if (!joinPath(path_, e.name, next, sizeof(next))) return;
    std::snprintf(path_, sizeof(path_), "%s", next);
    scan();
}

void SysFiles::ascend() {
    if (std::strcmp(path_, "/") == 0) return;
    char* slash = std::strrchr(path_, '/');
    if (slash == nullptr) return;
    if (slash == path_) std::snprintf(path_, sizeof(path_), "/");
    else                *slash = '\0';
    scan();
}

void SysFiles::openPreview(const Entry& e) {
    std::snprintf(previewName_, kNameLen, "%s", e.name);
    previewSize_ = e.size;
    previewLen_  = 0;
    previewLine_ = 0;
    previewText_ = looksTextual(e.name);
    preview_[0]  = '\0';

    char full[kPathLen];
    if (!joinPath(path_, e.name, full, sizeof(full))) {
        view_ = View::Preview;
        return;
    }

    File f = SD.open(full, FILE_READ);
    if (!f) {
        view_ = View::Preview;
        return;
    }
    previewLen_ = static_cast<uint16_t>(
        f.readBytes(preview_, kPreviewBytes));
    preview_[previewLen_] = '\0';
    f.close();

    view_ = View::Preview;
}

// ---- screens -----------------------------------------------------------------

void SysFiles::drawList() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u%s", static_cast<unsigned>(count_),
                  truncated_ ? "+" : "");
    ui::chrome("Files", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kBrass, kInk);
    d.drawString(path_, 8, kBodyTop - 6);

    if (count_ == 0) {
        d.setTextColor(kMuted, kInk);
        d.drawString("Empty.", 8, kBodyTop + 14);
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    if (selected_ >= static_cast<int>(count_)) selected_ = count_ - 1;
    if (selected_ < scroll_) scroll_ = selected_;
    if (selected_ >= scroll_ + kRows) scroll_ = selected_ - kRows + 1;

    for (int i = 0; i < kRows; i++) {
        const int idx = scroll_ + i;
        if (idx >= static_cast<int>(count_)) break;

        const Entry& e = entries_[idx];
        const int y   = kBodyTop + 8 + i * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (idx == selected_);
        ui::listRow(y, kRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);
        d.setTextDatum(middle_left);
        d.setTextColor(e.isDir ? kBrass : kText, bg);

        char label[34];
        std::snprintf(label, sizeof(label), "%s%.28s", e.isDir ? "/" : " ", e.name);
        d.drawString(label, 8, mid);

        if (!e.isDir) {
            char size[12];
            humanSize(e.size, size, sizeof(size));
            d.setTextDatum(middle_right);
            d.setTextColor(kFaint, bg);
            d.drawString(size, bd::kScreenW - 6, mid);
        }
    }

    d.setTextDatum(top_left);
    ui::footer("enter open   ` up");
    ui::endFrame();
}

void SysFiles::drawPreview() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char size[12];
    humanSize(previewSize_, size, sizeof(size));
    ui::chrome(previewName_, size);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    if (previewLen_ == 0) {
        d.setTextColor(kMuted, kInk);
        d.drawString("Empty, or could not be read.", 8, kBodyTop + 10);
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    const int maxLines = 7;
    int drawn = 0;

    if (previewText_) {
        // Walk to the first line of the window, then draw from there.
        int line = 0;
        uint16_t i = 0;
        while (line < previewLine_ && i < previewLen_) {
            if (preview_[i] == '\n') line++;
            i++;
        }
        while (drawn < maxLines && i < previewLen_) {
            char row[41] = {0};
            int n = 0;
            while (i < previewLen_ && preview_[i] != '\n' && n < 40) {
                const char c = preview_[i++];
                // A control byte would draw as a box or eat the rest of the row.
                row[n++] = (c >= 0x20 && c != 0x7F) ? c : ' ';
            }
            while (i < previewLen_ && preview_[i] != '\n') i++;  // clip the rest
            if (i < previewLen_) i++;                            // past the newline
            row[n] = '\0';
            d.setTextColor(kText, kInk);
            d.drawString(row, 8, kBodyTop + 4 + drawn * 11);
            drawn++;
        }
    } else {
        const int start = previewLine_ * kHexPerLine;
        for (int l = 0; l < maxLines; l++) {
            const int off = start + l * kHexPerLine;
            if (off >= previewLen_) break;

            char row[48];
            int n = std::snprintf(row, sizeof(row), "%04x ", off);
            for (int b = 0; b < kHexPerLine && off + b < previewLen_; b++) {
                n += std::snprintf(row + n, sizeof(row) - n, "%02x ",
                                   static_cast<uint8_t>(preview_[off + b]));
            }
            d.setTextColor(kText, kInk);
            d.drawString(row, 8, kBodyTop + 4 + l * 11);
            drawn++;
        }
    }

    if (previewSize_ > previewLen_) {
        ui::textAt(8, bd::kScreenH - kFooterH - 10, kFaint,
                   "first %u bytes of %s", static_cast<unsigned>(previewLen_), size);
    }

    d.setTextDatum(top_left);
    ui::footer("; . scroll   ` back");
    ui::endFrame();
}

void SysFiles::drawNoCard() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Files", "no card");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    d.drawString("No microSD card.", 8, kBodyTop + 10);
    d.setTextColor(kMuted, kInk);
    ui::wrapText(8, kBodyTop + 28, bd::kScreenW - 16, 11, 3, kMuted,
                 "Nothing this device has captured is lost -- it is in memory "
                 "until the surface that holds it is closed.");

    ui::footer("` back");
    ui::endFrame();
}

bool SysFiles::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (view_ == View::NoCard) return false;

    if (ks.enter) {
        if (view_ == View::List && count_) {
            const Entry& e = entries_[selected_];
            if (e.isDir) descend(e);
            else         openPreview(e);
        }
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Preview) { view_ = View::List; return true; }
                if (std::strcmp(path_, "/") != 0) { ascend(); return true; }
                return false;

            case kKeyUp:
                if (view_ == View::Preview) {
                    if (previewLine_ > 0) previewLine_--;
                } else if (selected_ > 0) {
                    selected_--;
                }
                return true;

            case kKeyDown:
                if (view_ == View::Preview) {
                    previewLine_++;
                } else if (selected_ + 1 < static_cast<int>(count_)) {
                    selected_++;
                }
                return true;

            default:
                break;
        }
    }
    return true;
}

void SysFiles::run() {
    lastDrawMs_ = 0;

    for (;;) {
        M5Cardputer.update();
        if (!handleKeys()) return;

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::List:    drawList();    break;
                case View::Preview: drawPreview(); break;
                case View::NoCard:  drawNoCard();  break;
            }
        }
        delay(5);
    }
}

}  // namespace orthrus::modules
