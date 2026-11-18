#include "ble_emulate.h"

#include <M5Cardputer.h>
#include <NimBLEDevice.h>

#include <cstdio>
#include <cstring>

#include "app/recorder.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"

namespace orthrus::modules {

using namespace orthrus::theme;
namespace bd  = orthrus::board;
namespace atk = orthrus::attack;
namespace ble = orthrus::ble;

namespace {

constexpr uint32_t kRedrawMs = 160;

constexpr int kBodyTop = 21;
constexpr int kRowH    = 14;
constexpr int kRows    = 6;

constexpr char kKeyUp   = ';';
constexpr char kKeyDown = '.';
constexpr char kKeyBack = '`';
constexpr char kKeyArm  = 'a';
constexpr char kKeyStop = 'x';

// The Bluetooth families, in the order the picker shows them: the four
// observational ones first, then the two that interrupt a person, then the
// swarm. The ordering is the warning -- an operator scrolling down walks from
// harmless to not.
constexpr atk::Family kBleFamilies[] = {
    atk::Family::BleFindMy,
    atk::Family::BleTile,
    atk::Family::BleSmartTag,
    atk::Family::BleFlipper,
    atk::Family::BleFastPair,
    atk::Family::BleSwiftPair,
    atk::Family::BleSwarm,
};
constexpr int kBleFamilyCount =
    static_cast<int>(sizeof(kBleFamilies) / sizeof(kBleFamilies[0]));

// Maps a family to the emulation that builds its payload. Returns false for
// Swarm, which has no single payload of its own.
bool emulationFor(atk::Family f, ble::Emulation& out) {
    switch (f) {
        case atk::Family::BleFindMy:    out = ble::Emulation::FindMy;    return true;
        case atk::Family::BleTile:      out = ble::Emulation::Tile;      return true;
        case atk::Family::BleSmartTag:  out = ble::Emulation::SmartTag;  return true;
        case atk::Family::BleFastPair:  out = ble::Emulation::FastPair;  return true;
        case atk::Family::BleSwiftPair: out = ble::Emulation::SwiftPair; return true;
        case atk::Family::BleFlipper:   out = ble::Emulation::Flipper;   return true;
        default: return false;
    }
}

uint16_t klassColour(atk::Klass k) {
    switch (k) {
        case atk::Klass::Disruptive: return kCritical;
        case atk::Klass::Active:     return kMedium;
        case atk::Klass::Benign:     return kLow;
    }
    return kMuted;
}

}  // namespace

bool BleEmulate::begin() {
    if (!bleUp_) {
        // A name is passed and then immediately overridden by every payload:
        // setAdvertisementData replaces the whole 31 bytes, so NimBLE's own
        // flags and name never reach the air. That matters for Find My, which
        // must fill the packet exactly with no flags structure at all.
        NimBLEDevice::init("");
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
        bleUp_ = true;
    }
    if (NimBLEDevice::getAdvertising() == nullptr) return false;

    // The authorisation. There is no target to pick -- these families aim at no
    // network -- so it is locked onto this device's own identity purely so the
    // gate has something to check, with the same four-hour-capped TTL as
    // everything else. The point is that the check HAPPENS: it used to be
    // skipped for exactly the families that need no target.
    uint8_t self[6] = {0x02, 0x4F, 0x52, 0x54, 0x48, 0x52};   // locally administered
    atk::lock(auth_, "ORTHRUS-BLE", self, 1, millis(), kAuthTtlMs);

    family_ = 0;
    scroll_ = 0;
    view_   = View::Families;
    return true;
}

void BleEmulate::enterArm() {
    atk::planDefault(plan_, kBleFamilies[family_]);
    planError_ = atk::validate(plan_, auth_, millis());
    holding_   = false;
    holdStart_ = 0;
    view_      = View::Arm;
}

bool BleEmulate::armIfHeld() {
    const bool down = M5Cardputer.Keyboard.isPressed() &&
                      M5Cardputer.Keyboard.isKeyPressed(kKeyArm);
    if (!down) { holding_ = false; return false; }
    if (!holding_) {
        holding_   = true;
        holdStart_ = millis();
        return false;
    }
    return (millis() - holdStart_) >= kArmHoldMs;
}

bool BleEmulate::advertise(const uint8_t* payload, size_t len, uint32_t salt) {
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    if (adv == nullptr || payload == nullptr || len == 0) return false;

    if (advertising_) adv->stop();

    // A random STATIC address, rotated with the identity. Static rather than
    // resolvable-private because a swarm whose members rotate underneath it
    // cannot be counted by the detector being tested, and a swarm nobody can
    // count is not a volume test.
    uint8_t rnd[6];
    ble::randomStaticAddress(rnd, salt);
    // NimBLEAddress takes the address least-significant byte first, which is
    // the reverse of how it is written down and of how randomStaticAddress
    // fills it.
    uint8_t swapped[6];
    for (int i = 0; i < 6; i++) swapped[i] = rnd[5 - i];
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
    ble_hs_id_set_rnd(swapped);

    NimBLEAdvertisementData data;
    // The payload is pushed whole. addData takes a char*, and the bytes are
    // ours exactly -- no flags, no name, no appended TX power -- because
    // several of these emulations are only recognisable at their real length.
    data.addData(reinterpret_cast<char*>(const_cast<uint8_t*>(payload)), len);
    adv->setAdvertisementData(data);

    // Non-connectable, no scan response: a tracker does not accept
    // connections, and offering one would make this emulation distinguishable
    // from the thing it is emulating. The two pairing families are the
    // exception in the real world, and are left non-connectable here on
    // purpose -- raising the dialog is the test, completing a pairing is not.
    adv->setScanResponse(false);
    adv->setMinInterval(0x00A0);   // 100 ms
    adv->setMaxInterval(0x00F0);   // 150 ms

    advertising_ = adv->start();
    return advertising_;
}

void BleEmulate::stopAdvertising() {
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    if (adv && advertising_) adv->stop();
    advertising_ = false;
}

void BleEmulate::startRun() {
    // Re-validated at the moment of arming, not of selection: the
    // authorisation may have expired while the operator read the screen.
    planError_ = atk::validate(plan_, auth_, millis());
    if (planError_ != atk::PlanError::Ok) return;

    rotations_  = 0;
    refused_    = 0;
    swarmStep_  = 0;
    runStart_   = millis();
    lastRotateMs_ = 0;   // forces the first payload out immediately
    lastKind_[0] = '\0';
    view_       = View::Running;
    stepRun();
}

void BleEmulate::stepRun() {
    if (view_ != View::Running) return;

    const uint32_t now = millis();

    // RE-CHECKED BEFORE EVERY ROTATION, not once at the start. That is what
    // bounds a long run: it ends when the authorisation expires.
    if (!auth_.valid(now)) {
        planError_ = atk::PlanError::AuthorizationExpired;
        finish();
        return;
    }

    if (!plan_.continuous && plan_.seconds != 0 &&
        (now - runStart_) >= static_cast<uint32_t>(plan_.seconds) * 1000u) {
        finish();   // stops on its own
        return;
    }

    const bool swarm = plan_.family == atk::Family::BleSwarm;
    const uint32_t every = swarm ? kSwarmRotateMs : 5000;
    if (lastRotateMs_ != 0 && (now - lastRotateMs_) < every) return;
    lastRotateMs_ = now;

    ble::Emulation e;
    if (swarm) {
        // swarmStep CANNOT return a family that raises a dialog -- the rotation
        // table in lib/core/ble/emulate.cpp excludes them, so asking for one by
        // mistake is not possible here.
        e = ble::swarmStep(swarmStep_++);
    } else if (!emulationFor(plan_.family, e)) {
        finish();
        return;
    }

    uint8_t payload[ble::kAdvertMax];
    const size_t len = ble::buildEmulation(e, payload, sizeof(payload),
                                           rotations_ + 1);
    if (len == 0) { refused_++; return; }

    if (advertise(payload, len, rotations_ + 1)) {
        rotations_++;
        std::strncpy(lastKind_, ble::emulationName(e), sizeof(lastKind_) - 1);
        lastKind_[sizeof(lastKind_) - 1] = '\0';
    } else {
        refused_++;
    }
}

void BleEmulate::finish() {
    stopAdvertising();

    const atk::Spec* s = atk::spec(plan_.family);
    char detail[160];
    std::snprintf(detail, sizeof(detail),
                  "emulate %s identities=%u refused=%u secs=%u dialog=%s",
                  s ? s->name : "?", static_cast<unsigned>(rotations_),
                  static_cast<unsigned>(refused_),
                  static_cast<unsigned>((millis() - runStart_) / 1000u),
                  (s && s->popsDialog) ? "yes" : "no");
    app::recorder().noteFinding(detail);

    view_ = View::Result;
}

// ---- screens ----------------------------------------------------------------

void BleEmulate::drawFamilies() {
    ui::beginFrame();
    auto& d = ui::gfx();
    ui::chrome("Emulate", "as a product");

    if (family_ < scroll_) scroll_ = family_;
    if (family_ >= scroll_ + kRows) scroll_ = family_ - kRows + 1;

    for (int row = 0; row < kRows; row++) {
        const int i = scroll_ + row;
        if (i >= kBleFamilyCount) break;
        const atk::Spec* s = atk::spec(kBleFamilies[i]);
        if (s == nullptr) continue;

        const int y   = kBodyTop + row * kRowH;
        const int mid = y + kRowH / 2;
        const bool sel = (i == family_);
        const uint16_t bg = sel ? kSurface : kInk;

        ui::listRow(y, kRowH, sel);

        d.setFont(kFaceData);
        d.setTextDatum(middle_left);
        d.setTextColor(sel ? kText : kMuted, bg);
        d.drawString(s->name, 8, mid);

        // THE MARK THAT MATTERS on this screen. Not the class -- the question
        // an operator needs answered before opening a row is whether a stranger
        // is about to get a dialog.
        d.setTextDatum(middle_right);
        if (s->popsDialog) {
            d.setTextColor(kCritical, bg);
            d.drawString("dialog", bd::kScreenW - 6, mid);
        } else {
            d.setTextColor(klassColour(s->klass), bg);
            d.drawString("quiet", bd::kScreenW - 6, mid);
        }
    }

    const atk::Spec* sel = atk::spec(kBleFamilies[family_]);
    ui::detailStrip(107, sel ? sel->proves : "");
    ui::footer("; . pick   enter open   ` back");
    d.setTextDatum(top_left);
    ui::endFrame();
}

void BleEmulate::drawArm() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const atk::Spec* s = atk::spec(plan_.family);
    ui::chrome(s ? s->name : "Arm");

    d.setFont(kFaceData);
    d.setTextDatum(top_left);

    // EFFECT FIRST, and in red when it reaches a person who did not ask.
    const int after = ui::wrapText(6, kHeaderH + 4, bd::kScreenW - 12, 9, 4,
                                   (s && s->popsDialog) ? kCritical : kText,
                                   s ? s->effect : "");
    int y = after + 4;

    if (planError_ != atk::PlanError::Ok) {
        d.setTextColor(kCritical, kInk);
        d.drawString(atk::planErrorText(planError_), 6, y);
        ui::footer("` back");
        ui::endFrame();
        return;
    }

    char line[56];
    if (plan_.seconds)
        std::snprintf(line, sizeof(line), "%us,  real vendor identifiers",
                      static_cast<unsigned>(plan_.seconds));
    else
        std::snprintf(line, sizeof(line), "until stopped,  real identifiers");
    d.setTextColor(kBrass, kInk);
    d.drawString(line, 6, y);
    y += 10;

    d.setTextColor(kFaint, kInk);
    d.drawString("Not a tracker -- a tracker's advert.", 6, y);

    const int barY = 118;
    d.drawRect(6, barY, bd::kScreenW - 12, 7, kRule);
    if (holding_) {
        uint32_t held = millis() - holdStart_;
        if (held > kArmHoldMs) held = kArmHoldMs;
        const int w = static_cast<int>((bd::kScreenW - 14) * held / kArmHoldMs);
        d.fillRect(7, barY + 1, w, 5, kShine);
    }

    ui::footer(holding_ ? "hold a ..." : "hold a  2s to arm    ` back");
    ui::endFrame();
}

void BleEmulate::drawRunning() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const atk::Spec* s = atk::spec(plan_.family);
    const uint32_t elapsed = (millis() - runStart_) / 1000u;
    char right[16];
    if (plan_.seconds)
        std::snprintf(right, sizeof(right), "%u/%us", static_cast<unsigned>(elapsed),
                      static_cast<unsigned>(plan_.seconds));
    else
        std::snprintf(right, sizeof(right), "%us", static_cast<unsigned>(elapsed));
    ui::chrome(s ? s->name : "Running", right);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    int y = kHeaderH + 8;
    char line[56];

    d.setTextColor(advertising_ ? kGood : kCritical, kInk);
    d.drawString(advertising_ ? "ON AIR" : "not advertising", 8, y);
    y += 14;

    d.setTextColor(kText, kInk);
    std::snprintf(line, sizeof(line), "identities %u",
                  static_cast<unsigned>(rotations_));
    d.drawString(line, 8, y);
    y += 11;

    if (plan_.family == atk::Family::BleSwarm && lastKind_[0]) {
        d.setTextColor(kBrass, kInk);
        std::snprintf(line, sizeof(line), "now: %s", lastKind_);
        d.drawString(line, 8, y);
        y += 11;
    }

    if (refused_) {
        d.setTextColor(kCritical, kInk);
        std::snprintf(line, sizeof(line), "refused by stack %u",
                      static_cast<unsigned>(refused_));
        d.drawString(line, 8, y);
        y += 11;
    }

    d.setTextColor(kFaint, kInk);
    std::snprintf(line, sizeof(line), "authorisation %u min left",
                  static_cast<unsigned>(auth_.remainingMs(millis()) / 60000u));
    d.drawString(line, 8, y);

    ui::footer("x  stop");
    ui::endFrame();
}

void BleEmulate::drawResult() {
    ui::beginFrame();
    auto& d = ui::gfx();

    const atk::Spec* s = atk::spec(plan_.family);
    ui::chrome("Result", s ? s->name : nullptr);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    int y = kHeaderH + 6;
    char line[64];

    d.setTextColor(kText, kInk);
    std::snprintf(line, sizeof(line), "%u identities advertised",
                  static_cast<unsigned>(rotations_));
    d.drawString(line, 8, y);
    y += 13;

    // THE CEILING, every time. This proves what a detector did with these
    // bytes, and nothing about whether a real product would behave the same.
    y = ui::wrapText(8, y, bd::kScreenW - 16, 10, 5, kMuted,
                     "What a detector did with these bytes is the result. This "
                     "was never a tracker -- a real one rotates a resolvable "
                     "key and answers the vendor's cryptography.");

    if (refused_) {
        d.setTextColor(kCritical, kInk);
        std::snprintf(line, sizeof(line), "%u refused by the stack",
                      static_cast<unsigned>(refused_));
        d.drawString(line, 8, 112);
    }

    ui::footer("` back");
    ui::endFrame();
}

void BleEmulate::draw() {
    switch (view_) {
        case View::Families: drawFamilies(); break;
        case View::Arm:      drawArm();      break;
        case View::Running:  drawRunning();  break;
        case View::Result:   drawResult();   break;
    }
    lastDrawMs_ = millis();
}

bool BleEmulate::handleKeys() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
        return false;

    const auto ks = M5Cardputer.Keyboard.keysState();

    if (ks.enter) {
        if (view_ == View::Families) { enterArm(); draw(); }
        return false;
    }

    for (char c : ks.word) {
        switch (view_) {
            case View::Families:
                if (c == kKeyUp   && family_ > 0) family_--;
                if (c == kKeyDown && family_ + 1 < kBleFamilyCount) family_++;
                if (c == kKeyBack) return true;
                break;

            case View::Arm:
                if (c == kKeyBack) { view_ = View::Families; holding_ = false; }
                break;

            case View::Running:
                if (c == kKeyStop) finish();
                break;

            case View::Result:
                if (c == kKeyBack) view_ = View::Families;
                break;
        }
    }
    draw();
    return false;
}

void BleEmulate::run() {
    draw();

    for (;;) {
        M5Cardputer.update();

        if (handleKeys()) break;

        if (view_ == View::Arm && planError_ == atk::PlanError::Ok) {
            if (armIfHeld()) startRun();
        }
        if (view_ == View::Running) stepRun();

        if (millis() - lastDrawMs_ >= kRedrawMs) draw();
        delay(5);
    }

    // Always leave the radio quiet. A surface that exits still advertising as
    // somebody's luggage tag is the worst failure this file could have.
    stopAdvertising();
    atk::unlock(auth_);
}

}  // namespace orthrus::modules
