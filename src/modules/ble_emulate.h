// Emulate: advertise as a real product, to test what notices.
//
// WHAT THIS IS FOR
//
// Every tracker detector, device-spam alarm and asset-tracking app classifies
// by a manufacturer company identifier or a service UUID. It has to: a name is
// a string somebody typed, and half the trackers in the world are called
// "iPhone". So testing one of those detectors means putting the real
// identifiers on the air. An advertisement built from the Bluetooth SIG's
// reserved test identifier would be correctly ignored, and a test that passes
// because the detector ignored it has established nothing.
//
// That is the one deliberate exception to this device's test-prefix rule, and
// it is stated here, in attack::familyMayImpersonate, and in
// lib/core/ble/emulate.h, rather than being quietly true.
//
// THE TWO THAT INTERRUPT A PERSON
//
// Find My, Tile, SmartTag and Flipper are observational: a phone in range
// relays or ignores them and shows its owner nothing. Fast Pair and Swift Pair
// are pairing solicitations, and they put a dialog in front of whoever is
// holding the phone -- in a shared building, that is strangers.
//
// So the arming screen leads with the effect, those two are marked, their rate
// and duration ceilings are a fraction of the others', and the Swarm rotation
// CANNOT reach them: lib/core/ble/emulate.cpp's rotation table excludes them,
// so the guard is the code rather than a note in a manual.
//
// AND THE CEILING ON WHAT IT PROVES
//
// This proves what a detector does with these bytes. It does not prove a real
// AirTag would behave identically -- a real one rotates its key on a schedule,
// answers Apple's cryptography, and is attached to something. Nothing here is
// a tracker. It is a tracker's advertisement, which is a smaller and checkable
// claim, and the result screen says so.

#pragma once

#include <cstdint>

#include "attack/family.h"
#include "ble/emulate.h"

namespace orthrus::modules {

class BleEmulate {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { Families, Arm, Running, Result };

    // Held, not tapped -- the same doctrine as the Wi-Fi surface. Two of these
    // families interrupt people who did not ask.
    static constexpr uint32_t kArmHoldMs = 2000;

    // The authorisation this surface locks. These families need no target, and
    // that is exactly why they are checked against one: the families that need
    // no target are the ones that look like they need no permission.
    static constexpr uint32_t kAuthTtlMs = 60u * 60u * 1000u;

    // How often the advertised identity is rotated during a swarm, in
    // milliseconds. Slow enough that a scanner gets several sightings of each
    // one -- a swarm nobody can count is not a volume test.
    static constexpr uint32_t kSwarmRotateMs = 1200;

    void enterArm();
    bool armIfHeld();
    void startRun();
    void stepRun();
    void finish();

    // Pushes one payload to the radio. Returns false when the stack refused it.
    bool advertise(const uint8_t* payload, size_t len, uint32_t salt);
    void stopAdvertising();

    void drawFamilies();
    void drawArm();
    void drawRunning();
    void drawResult();
    void draw();
    bool handleKeys();

    int  family_ = 0;      // index into the BLE family list
    int  scroll_ = 0;

    attack::Authorization auth_;
    attack::Plan          plan_;
    attack::PlanError     planError_ = attack::PlanError::NotAuthorized;

    uint32_t holdStart_ = 0;
    bool     holding_   = false;

    bool     bleUp_       = false;
    bool     advertising_ = false;

    uint32_t runStart_    = 0;
    uint32_t lastRotateMs_ = 0;
    uint32_t rotations_   = 0;
    uint32_t swarmStep_   = 0;
    uint32_t refused_     = 0;
    char     lastKind_[16] = {0};

    View     view_       = View::Families;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
