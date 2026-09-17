#include "nfc_read.h"

#include <M5Cardputer.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "credential/defaults.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace cr = orthrus::credential;

namespace {

constexpr uint32_t kRedrawMs = 160;
constexpr uint32_t kPollMs   = 90;

constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';

constexpr int kBodyTop  = 21;
constexpr int kRollRowH = 14;
constexpr int kRollRows = 6;

void uidToHex(const cr::TagIdentity& t, char* out, size_t cap) {
    size_t n = 0;
    for (uint8_t i = 0; i < t.uidLen && n + 3 < cap; i++)
        n += static_cast<size_t>(std::snprintf(out + n, cap - n, "%02X", t.uid[i]));
    out[n] = '\0';
}

}  // namespace

bool NfcRead::begin() {
    // Port probing lives in the HAL now, because Keys needs the same reader on
    // the same port and two copies of that logic would eventually disagree.
    return hal::openSharedReader(&busName_);
}

int NfcRead::findInRoll(const cr::TagIdentity& t) const {
    for (uint8_t i = 0; i < rollCount_; i++) {
        if (roll_[i].tag.uidLen == t.uidLen &&
            std::memcmp(roll_[i].tag.uid, t.uid, t.uidLen) == 0)
            return static_cast<int>(i);
    }
    return -1;
}

void NfcRead::poll() {
    if (millis() - lastPollMs_ < kPollMs) return;
    lastPollMs_ = millis();

    cr::TagIdentity t;
    const hal::ReaderStatus st = reader_.poll(t);
    pollCount_++;
    lastStatus_ = st;

    if (st != hal::ReaderStatus::Ok) {
        // "No card" is the normal state, not an error, and counting it as one
        // would make the error tally meaningless.
        if (st != hal::ReaderStatus::NoCard) errorCount_++;
        return;
    }

    lastReadMs_ = millis();

    const int existing = findInRoll(t);
    if (existing >= 0) {
        roll_[existing].count++;
        roll_[existing].tag = t;
        selected_ = existing;
    } else {
        if (rollCount_ >= kRollMax) {
            // Evict the oldest. Keeping the oldest instead left selected_ at
            // -1, which bounced the card view straight back to Waiting -- so
            // from the thirteenth badge onwards, tapping a card showed nothing
            // at all. On an engagement the newest badge is the one in your
            // hand, so that is the one to keep.
            for (uint8_t i = 1; i < kRollMax; i++) roll_[i - 1] = roll_[i];
            rollCount_ = kRollMax - 1;
        }
        roll_[rollCount_].tag     = t;
        roll_[rollCount_].firstMs = millis();
        roll_[rollCount_].count   = 1;
        selected_ = rollCount_;
        rollCount_++;
    }

    if (existing < 0) {
        probeNote_ = nullptr;  // a new badge, not the old result
        logBadge(t);
    }
    if (view_ == View::Waiting) view_ = View::Card;

    // Put the card to sleep so the next poll sees a genuinely new presentation
    // rather than the same badge answering forever.
    reader_.halt();
}

void NfcRead::runKeyProbe() {
    if (selected_ < 0 || selected_ >= static_cast<int>(rollCount_)) return;
    cr::TagIdentity& t = roll_[selected_].tag;

    if (!t.isClassicCompatible()) {
        probeNote_ = "no Crypto1 sectors to try";
        return;
    }

    // Tell the operator what is happening before blocking for a second or two,
    // and tell them to keep the card there -- the probe needs it.
    ui::beginFrame();
    ui::chrome("Key probe");
    auto& d = ui::gfx();
    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kText, kInk);
    d.drawString("Trying published default keys", 8, kBodyTop + 14);
    d.setTextColor(kBrass, kInk);
    d.drawString("KEEP THE CARD ON THE READER", 8, kBodyTop + 34);
    d.setTextColor(kFaint, kInk);
    d.drawString("read only - nothing is written", 8, kBodyTop + 54);
    ui::footer("working...");
    ui::endFrame();

    uint8_t keyIndex = 0, keyType = 0;
    const bool opened = reader_.probeDefaultKeys(t, &keyIndex, &keyType);

    // If the card never answered, saying "no published key opened it" would be
    // a finding we did not earn: we never got to ask.
    if (!opened && !reader_.lastProbeSawCard()) {
        probeNote_ = "card gone - hold it steady and retry";
        t.triedDefaultKeys = false;   // do not record a probe that never ran
        view_ = View::Card;
        return;
    }

    if (opened) {
        const cr::DefaultKey& k = cr::defaultKeys()[keyIndex];
        std::snprintf(probeBuf_, sizeof(probeBuf_), "key %c: %s",
                      keyType == 0 ? 'A' : 'B', k.origin);
        probeNote_ = probeBuf_;

        char uid[24];
        uidToHex(t, uid, sizeof(uid));
        char detail[96];
        std::snprintf(detail, sizeof(detail),
                      "uid=%s finding=default-key-accepted key=%c origin=%s", uid,
                      keyType == 0 ? 'A' : 'B', k.origin);
        app::recorder().noteFinding(detail);
    } else {
        probeNote_ = "no published key opened it";
    }
    view_ = View::Card;
}

void NfcRead::logBadge(const cr::TagIdentity& t) {
    auto& r = app::recorder();
    if (!r.active()) return;

    char uid[24];
    uidToHex(t, uid, sizeof(uid));
    const auto a = cr::assess(t);

    char detail[96];
    int n = std::snprintf(detail, sizeof(detail), "uid=%s family=%s grade=%s", uid,
                          cr::familyName(t.family()), cr::gradeName(a.grade));
    if (gnss_.hasFix() && n > 0 && n < static_cast<int>(sizeof(detail))) {
        std::snprintf(detail + n, sizeof(detail) - n, " lat=%.5f lon=%.5f",
                      gnss_.latitude(), gnss_.longitude());
    }
    r.noteDevice(detail);
}

void NfcRead::drawWaiting() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[20];
    std::snprintf(right, sizeof(right), "%s v%02X", busName_, reader_.chipVersion());
    ui::chrome("Read Card", right);

    d.setFont(kFaceUi);
    d.setTextDatum(middle_center);
    d.setTextColor(kText, kInk);
    d.drawString("Hold a badge to the reader", bd::kScreenW / 2, kBodyTop + 22);

    d.setFont(kFaceData);
    d.setTextColor(kFaint, kInk);
    d.drawString("13.56 MHz  -  read only, no keys tried",
                 bd::kScreenW / 2, kBodyTop + 44);

    // A visible pulse so the operator can see it is actually scanning rather
    // than hung.
    const int dots = static_cast<int>((millis() / 350) % 4);
    char pulse[8] = {0};
    for (int i = 0; i < dots; i++) pulse[i] = '.';
    d.setTextColor(kShine, kInk);
    d.drawString(pulse, bd::kScreenW / 2, kBodyTop + 64);

    d.setTextDatum(middle_left);
    d.setTextColor(kFaint, kInk);
    char stat[40];
    std::snprintf(stat, sizeof(stat), "%lu polls   %lu seen",
                  static_cast<unsigned long>(pollCount_),
                  static_cast<unsigned long>(rollCount_));
    d.drawString(stat, 6, kBodyTop + 84);

    d.setTextDatum(top_left);
    ui::footer(rollCount_ ? "enter roll   ` back" : "` back");
    ui::endFrame();
}

void NfcRead::drawCard() {
    if (selected_ < 0 || selected_ >= static_cast<int>(rollCount_)) {
        view_ = View::Waiting;
        return;
    }

    ui::beginFrame();
    auto& d = ui::gfx();

    const cr::TagIdentity& t = roll_[selected_].tag;
    const auto a = cr::assess(t);
    const cr::Family fam = t.family();

    char uid[24];
    uidToHex(t, uid, sizeof(uid));
    ui::chrome("Badge", uid);

    // The grade, large, in the identity face.
    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_left);
    d.setTextColor(ui::gradeColour(a.grade), kInk);
    d.drawString(cr::gradeName(a.grade), 8, kBodyTop + 14);

    d.setFont(kFaceData);
    ui::textAt(52, kBodyTop + 6, kText, "%s", cr::familyName(fam));
    ui::textAt(52, kBodyTop + 19, kMuted, "%s", cr::cipherName(cr::cipherFor(fam)));

    ui::textRight(bd::kScreenW - 6, kBodyTop + 6, kFaint, "%u/100",
                  static_cast<unsigned>(a.score));

    d.drawFastHLine(6, kBodyTop + 30, bd::kScreenW - 12, kRule);

    ui::textAt(8, kBodyTop + 42, kMuted, "%s", cr::uidKindName(t.uidKind()));
    ui::textRight(bd::kScreenW - 6, kBodyTop + 42, kFaint, "ATQA %04X SAK %02X",
                  t.atqa, t.sak);

    // Lead with the single most serious finding: it is what the operator needs
    // in the two seconds they are looking at the screen.
    if (a.findings.count > 0) {
        const cr::Finding& top = a.findings.items[0];
        ui::textAt(8, kBodyTop + 60, ui::severityColour(top.sev),
                   "%s", cr::findingTitle(top.id));
        if (a.findings.count > 1) {
            ui::textAt(8, kBodyTop + 73, kFaint, "+%u more",
                       static_cast<unsigned>(a.findings.count - 1));
        }
    }

    if (probeNote_ != nullptr) {
        ui::textAt(8, kBodyTop + 84, a.findings.has(cr::FindingId::DefaultKeyAccepted)
                                         ? kCritical : kMuted,
                   "%s", probeNote_);
    } else if (a.surfaceOnly) {
        ui::textRight(bd::kScreenW - 6, kBodyTop + 73, kFaint, "surface read");
    }

    d.setTextDatum(top_left);
    ui::footer("enter findings  k keys  r roll  ` back");
    ui::endFrame();
}

void NfcRead::drawDossier() {
    if (selected_ < 0 || selected_ >= static_cast<int>(rollCount_)) {
        view_ = View::Waiting;
        return;
    }

    ui::beginFrame();
    auto& d = ui::gfx();

    const cr::TagIdentity& t = roll_[selected_].tag;
    const auto a = cr::assess(t);

    char uid[24];
    uidToHex(t, uid, sizeof(uid));
    ui::chrome("Findings", uid);

    int y = kBodyTop + 6;
    const int listLimit = bd::kScreenH - kFooterH - 40;
    uint8_t shown = 0;

    for (uint8_t i = 0; i < a.findings.count && y < listLimit; i++) {
        const cr::Finding& f = a.findings.items[i];
        ui::textAt(8, y, ui::severityColour(f.sev),
                   "%s", cr::findingTitle(f.id));
        if (cr::findingCarriesConfidence(f.sev)) {
            ui::textRight(bd::kScreenW - 6, y, kFaint, "%u%%",
                          static_cast<unsigned>(f.confidence));
        }
        y += 12;
        shown++;
    }
    if (shown < a.findings.count) {
        ui::textAt(8, y, kFaint, "+%u more",
                   static_cast<unsigned>(a.findings.count - shown));
    }

    // The explanation of the most serious one. A finding without its
    // explanation is just an accusation.
    if (a.findings.count > 0) {
        const int ruleY = bd::kScreenH - kFooterH - 36;
        d.drawFastHLine(6, ruleY, bd::kScreenW - 12, kRule);
        d.setFont(kFaceData);
        ui::wrapText(8, ruleY + 5, bd::kScreenW - 16, 10, 3, kMuted,
                     cr::findingDetail(a.findings.items[0].id));
    }

    d.setTextDatum(top_left);
    ui::footer("` back");
    ui::endFrame();
}

void NfcRead::drawRoll() {
    ui::beginFrame();
    auto& d = ui::gfx();

    char right[16];
    std::snprintf(right, sizeof(right), "%u badges",
                  static_cast<unsigned>(rollCount_));
    ui::chrome("Roll", right);

    if (rollCount_ == 0) {
        d.setFont(kFaceData);
        d.setTextDatum(top_left);
        d.setTextColor(kMuted, kInk);
        d.drawString("Nothing presented yet.", 8, kBodyTop + 10);
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    for (int i = 0; i < kRollRows && i < static_cast<int>(rollCount_); i++) {
        const Seen& s = roll_[i];
        const auto a = cr::assess(s.tag);

        const int y   = kBodyTop + i * kRollRowH;
        const int mid = y + kRollRowH / 2;
        const bool sel = (i == selected_);
        ui::listRow(y, kRollRowH, sel);

        const uint16_t bg = sel ? kSurface : kInk;
        d.setFont(kFaceData);

        char uid[24];
        uidToHex(s.tag, uid, sizeof(uid));

        d.setTextDatum(middle_left);
        d.setTextColor(kText, bg);
        d.drawString(uid, 8, mid);

        d.setTextColor(kMuted, bg);
        d.drawString(cr::familyName(s.tag.family()), 90, mid);

        d.setTextDatum(middle_right);
        d.setTextColor(ui::gradeColour(a.grade), bg);
        d.drawString(cr::gradeName(a.grade), bd::kScreenW - 8, mid);
    }

    d.setTextDatum(top_left);
    ui::footer("enter open   ; . move   ` back");
    ui::endFrame();
}

bool NfcRead::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return true;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (ks.enter) {
        if (view_ == View::Waiting && rollCount_) view_ = View::Roll;
        else if (view_ == View::Card)            view_ = View::Dossier;
        else if (view_ == View::Roll)            view_ = View::Card;
        return true;
    }

    for (char c : ks.word) {
        switch (c) {
            case kKeyBack:
                if (view_ == View::Dossier)   view_ = View::Card;
                else if (view_ == View::Card) view_ = View::Waiting;
                else if (view_ == View::Roll) view_ = View::Waiting;
                else return false;
                return true;

            case kKeyUp:
                if (selected_ > 0) selected_--;
                return true;

            case kKeyDown:
                if (selected_ + 1 < static_cast<int>(rollCount_)) selected_++;
                return true;

            case 'r':
                if (rollCount_) view_ = View::Roll;
                return true;

            case 'k':
                // Only meaningful on a Crypto1 card, and only with the badge
                // still on the reader -- the probe re-selects between attempts.
                if (view_ == View::Card || view_ == View::Dossier) runKeyProbe();
                return true;

            default:
                break;
        }
    }
    return true;
}

void NfcRead::run() {
    for (;;) {
        M5Cardputer.update();

        // Keep scanning in every view: an operator browsing findings still
        // wants the next badge picked up without going back first.
        poll();

        if (!handleKeys()) {
            // Leave the field off. The reader draws about 26 mA with the
            // antenna live, on a device meant to be carried all day.
            reader_.antennaOff();
            return;
        }

        if (millis() - lastDrawMs_ >= kRedrawMs) {
            lastDrawMs_ = millis();
            switch (view_) {
                case View::Waiting: drawWaiting(); break;
                case View::Card:    drawCard();    break;
                case View::Dossier: drawDossier(); break;
                case View::Roll:    drawRoll();    break;
            }
        }
        delay(2);
    }
}

}  // namespace orthrus::modules
