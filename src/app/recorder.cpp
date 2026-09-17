#include "recorder.h"

#include <M5Cardputer.h>
#include <SD.h>

#include <cstdio>
#include <cstring>

#include "crypto/sha256.h"
#include "evidence/export.h"
#include "hal/board.h"
#include "hal/lora_radio.h"

namespace orthrus::app {

using namespace orthrus::evidence;

namespace {
constexpr const char* kDir = "/orthrus";
}

bool Recorder::openSessionFile() {
    if (!SD.exists(kDir) && !SD.mkdir(kDir)) {
        lastError_ = "cannot create /orthrus";
        return false;
    }

    // Find the next free index rather than a timestamp: there is no RTC on this
    // board, so every boot would otherwise claim the same filename and sessions
    // would overwrite each other.
    for (int i = 1; i < 1000; i++) {
        std::snprintf(path_, sizeof(path_), "%s/session-%03d.csv", kDir, i);
        if (!SD.exists(path_)) break;
        path_[0] = '\0';
    }
    if (path_[0] == '\0') {
        lastError_ = "no free session filename";
        return false;
    }

    // Seed the chain from something session-specific, so two sessions cannot
    // produce the same digests even with identical contents.
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    std::snprintf(seed_, sizeof(seed_), "orthrus/%02X%02X%02X%02X%02X%02X/%s",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], path_);
    chain_.begin(seed_, std::strlen(seed_));

    File f = SD.open(path_, FILE_WRITE);
    if (!f) {
        lastError_ = "cannot open session file";
        return false;
    }
    char header[96];
    csvHeader(header, sizeof(header));
    f.print(header);
    f.close();

    active_ = true;
    lastError_ = "";
    return true;
}

bool Recorder::begin() {
    if (active_) return true;

    // Tried once per boot. Retrying the mount on every record would stall the
    // capture loop for seconds at a time when no card is present.
    if (attempted_) return false;
    attempted_ = true;

    // Shares the bus with the radio; only the chip selects differ.
    if (!SD.begin(board::kSdCs, hal::sharedSpi(), 20000000)) {
        lastError_ = "no microSD card";
        active_    = false;
        return false;
    }
    if (!openSessionFile()) return false;

    note(RecordKind::SessionStart, "orthrus session opened");
    return true;
}

bool Recorder::note(RecordKind kind, const char* detail) {
    // Opened on first use rather than at boot: a session file created every
    // power cycle would litter the card with empty logs from people who just
    // switched the device on to look at it.
    if (!active_ && !begin()) return false;

    Record r;
    r.seq    = chain_.count();
    r.timeMs = millis();
    r.kind   = kind;
    std::snprintf(r.detail, kDetailLen, "%s", detail ? detail : "");

    // Build the line BEFORE advancing the chain. If the write fails the chain
    // must not move, or the digest held in memory would describe a record that
    // never reached the card.
    Chain probe = chain_;
    uint8_t head[crypto::kSha256DigestLen];
    probe.append(r, head);

    char line[kDetailLen * 2 + 160];
    if (csvRow(line, sizeof(line), r, head) == 0) {
        lastError_ = "record too long to serialise";
        failures_++;
        return false;
    }

    File f = SD.open(path_, FILE_APPEND);
    if (!f) {
        lastError_ = "cannot append";
        failures_++;
        return false;
    }
    const size_t wrote = f.print(line);
    f.close();

    if (wrote == 0) {
        lastError_ = "write returned zero";
        failures_++;
        return false;
    }

    chain_ = probe;  // only now is the record part of the chain
    lastError_ = "";
    return true;
}

void Recorder::headHex(char out[65]) const {
    crypto::toHex(chain_.head(), out);
}

void Recorder::headShort(char out[24]) const {
    char full[65];
    crypto::toHex(chain_.head(), full);
    std::snprintf(out, 24, "%.8s..%.8s", full, full + 56);
}

Recorder& recorder() {
    static Recorder instance;
    return instance;
}

}  // namespace orthrus::app
