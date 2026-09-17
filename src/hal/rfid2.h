// M5Stack RFID2 unit (WS1850S) over I2C.
//
// Written out rather than pulled from an MFRC522 library so the transceive path
// is one file you can read top to bottom. That matters here: every byte this
// code parses comes off a card that an attacker may have built, so the length
// handling is the security-relevant part and it should not be buried in a
// dependency.
//
// The WS1850S is register-compatible with the MFRC522. Its I2C address is 0x28.
//
// Scope: ISO14443-A anticollision and SELECT, the full UID cascade, and RATS
// for ISO-DEP cards. That is everything needed to identify and grade a badge
// without authenticating to it -- which is exactly the attacker's view.

#pragma once

#include <M5Unified.h>

#include <cstdint>

#include "credential/tag.h"

namespace orthrus::hal {

enum class ReaderStatus : uint8_t {
    Ok = 0,
    NoCard,
    Timeout,
    CollisionError,
    ChecksumError,   // the card's own BCC did not match
    ProtocolError,
    NotPresent,      // no reader on the bus
};

class Rfid2 {
public:
    // Probes a bus and initialises the reader. Safe to call repeatedly.
    //
    // The bus is a parameter because the Cardputer-Adv has TWO Grove ports once
    // the LoRa cap is fitted: the board's own Port A on G1/G2 (M5.Ex_I2C) and
    // the cap's pass-through on G8/G9, which is the internal bus (M5.In_I2C).
    // That is what lets the NFC and RFID2 units both be connected at once.
    bool begin(m5::I2C_Class* bus, uint8_t i2cAddress = 0x28);

    bool present() const { return present_; }
    uint8_t chipVersion() const { return version_; }

    // Looks for a card and, if one answers, runs the full cascade.
    //
    // `tag` is only written when this returns Ok. Everything filled in comes
    // from anticollision alone: no keys, no authentication, nothing the
    // cardholder would notice.
    ReaderStatus poll(credential::TagIdentity& tag);

    // Tells a selected card to stop answering, so the next poll sees a fresh
    // one rather than the same card over and over.
    void halt();

    // Tries the published default keys against sector 0.
    //
    // READ ONLY. It authenticates and stops; it never writes a block, never
    // changes a key, and never touches the access bits. Proving a badge still
    // carries its factory key is the finding -- altering it would be vandalism.
    //
    // This is not a key-recovery attack: no nested or darkside cracking is
    // implemented. If none of the published keys open it, the honest answer is
    // "we could not open it".
    //
    // Sets tag.triedDefaultKeys either way, and on success sets
    // tag.defaultKeyAccepted. `keyIndexOut` receives the index into
    // credential::defaultKeys(), `keyTypeOut` 0 for key A or 1 for key B.
    bool probeDefaultKeys(credential::TagIdentity& tag,
                          uint8_t* keyIndexOut = nullptr,
                          uint8_t* keyTypeOut = nullptr);

    // How many attempts probeDefaultKeys will make, for a progress indicator.
    static uint16_t probeAttemptCount();

    // True if the card answered anticollision at least once during the last
    // probe. Without this, a card lifted off the reader mid-probe is
    // indistinguishable from a card that refused every key -- and reporting
    // "no published key opened it" for a card we never spoke to is a finding
    // we did not earn.
    bool lastProbeSawCard() const { return lastProbeSawCard_; }

    // Turns the field off. The reader draws ~26 mA with the antenna live and
    // this is a battery device.
    void antennaOff();
    void antennaOn();

    const char* lastError() const { return lastError_; }

private:
    bool readReg(uint8_t reg, uint8_t& value) const;
    bool readRegs(uint8_t reg, uint8_t* out, size_t len) const;
    bool writeReg(uint8_t reg, uint8_t value) const;
    bool setRegBits(uint8_t reg, uint8_t mask) const;
    bool clearRegBits(uint8_t reg, uint8_t mask) const;

    // Sends and receives one frame. `rxLen` is in/out: capacity on the way in,
    // bytes received on the way out.
    ReaderStatus transceive(const uint8_t* tx, uint8_t txLen, uint8_t txLastBits,
                            uint8_t* rx, uint8_t& rxLen, uint8_t* rxLastBits,
                            bool checkCrc = false);

    bool calculateCrc(const uint8_t* data, uint8_t len, uint8_t out[2]);

    ReaderStatus requestA(uint16_t& atqa);
    ReaderStatus cascade(credential::TagIdentity& tag);
    ReaderStatus requestAts(credential::TagIdentity& tag);

    ReaderStatus authenticate(uint8_t keyType, uint8_t block, const uint8_t key[6],
                              const credential::TagIdentity& tag);
    void         stopCrypto1();
    ReaderStatus reselect(credential::TagIdentity& tag);

    m5::I2C_Class* bus_ = nullptr;
    uint8_t     address_ = 0x28;
    bool        present_ = false;
    uint8_t     version_ = 0;
    const char* lastError_ = "";
    bool        lastProbeSawCard_ = false;
};

const char* readerStatusName(ReaderStatus s);

}  // namespace orthrus::hal
