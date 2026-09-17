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

    // The bus has to be up before the card can be found on it. This used to be
    // done only by the radio, which meant the card was invisible on any boot
    // where a radio surface had not been opened first -- and "no microSD card"
    // is a very convincing thing for a device to say when the real problem is
    // that nothing had assigned pins to the SPI bus yet.
    hal::beginSharedSpi();

    // Shares the bus with the radio; only the chip selects differ.
    //
    // Three speeds, fastest first. A shared bus with a cap on top of it has
    // longer traces than the SD card was designed for, and plenty of otherwise
    // healthy cards refuse to enumerate at 20 MHz while working perfectly at 4.
    // Reporting "no card" because of a clock rate would send someone hunting
    // for a fault in the wrong place.
    static constexpr uint32_t kSpeeds[] = {20000000, 10000000, 4000000};
    bool mounted = false;
    for (uint32_t hz : kSpeeds) {
        if (SD.begin(board::kSdCs, hal::sharedSpi(), hz)) {
            mounted = true;
            mountHz_ = hz;
            break;
        }
        SD.end();
        delay(20);
    }

    if (!mounted) {
        lastError_ = "no microSD card";
        active_    = false;
        return false;
    }

    // A card that mounts but reports no type is not a card we should write an
    // engagement to.
    if (SD.cardType() == CARD_NONE) {
        lastError_ = "card did not identify itself";
        active_    = false;
        SD.end();
        return false;
    }
    cardMiB_ = static_cast<uint32_t>(SD.cardSize() / (1024ULL * 1024ULL));
    if (!openSessionFile()) return false;

    note(RecordKind::SessionStart, "orthrus session opened");
    return true;
}

void Recorder::retry() {
    // Only the "we looked and found nothing" state is worth retrying. An open
    // session must not be torn down and reopened underneath a running capture.
    if (active_) return;
    attempted_ = false;
    lastError_ = "";
    begin();
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

    // Sanitised before hashing, not after. The chain has to cover exactly the
    // bytes that land on the card, and a control byte here would otherwise be
    // stripped by the CSV writer and the digest would describe text that was
    // never written.
    char raw[kDetailLen];
    std::snprintf(raw, sizeof(raw), "%s", detail ? detail : "");
    sanitiseText(raw, r.detail, kDetailLen);

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
