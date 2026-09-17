#include "rfid2.h"

#include <M5Cardputer.h>

#include <cstring>

#include "board.h"
#include "credential/defaults.h"

namespace orthrus::hal {

using credential::kMaxAtsLen;
using credential::kMaxUidLen;

namespace {

constexpr uint32_t kI2cFreq = 100000;

// MFRC522 / WS1850S registers. Over I2C these are addressed directly, unlike
// the SPI interface which shifts and flags them.
constexpr uint8_t REG_COMMAND      = 0x01;
constexpr uint8_t REG_COM_IRQ      = 0x04;
constexpr uint8_t REG_ERROR        = 0x06;
constexpr uint8_t REG_STATUS2      = 0x08;
constexpr uint8_t REG_FIFO_DATA    = 0x09;
constexpr uint8_t REG_FIFO_LEVEL   = 0x0A;
constexpr uint8_t REG_CONTROL      = 0x0C;
constexpr uint8_t REG_BIT_FRAMING  = 0x0D;
constexpr uint8_t REG_COLL         = 0x0E;
constexpr uint8_t REG_MODE         = 0x11;
constexpr uint8_t REG_TX_CONTROL   = 0x14;
constexpr uint8_t REG_TX_ASK       = 0x15;
constexpr uint8_t REG_CRC_RESULT_H = 0x21;
constexpr uint8_t REG_CRC_RESULT_L = 0x22;
constexpr uint8_t REG_T_MODE       = 0x2A;
constexpr uint8_t REG_T_PRESCALER  = 0x2B;
constexpr uint8_t REG_T_RELOAD_H   = 0x2C;
constexpr uint8_t REG_T_RELOAD_L   = 0x2D;
constexpr uint8_t REG_VERSION      = 0x37;

constexpr uint8_t CMD_IDLE       = 0x00;
constexpr uint8_t CMD_CALC_CRC   = 0x03;
constexpr uint8_t CMD_MF_AUTHENT = 0x0E;
constexpr uint8_t CMD_TRANSCEIVE = 0x0C;
constexpr uint8_t CMD_SOFT_RESET = 0x0F;

// PICC commands (ISO/IEC 14443-3).
constexpr uint8_t PICC_REQA   = 0x26;
constexpr uint8_t PICC_HLTA   = 0x50;
constexpr uint8_t PICC_RATS   = 0xE0;
constexpr uint8_t PICC_AUTH_KEY_A = 0x60;
constexpr uint8_t PICC_AUTH_KEY_B = 0x61;
constexpr uint8_t PICC_SEL_CL1 = 0x93;
constexpr uint8_t PICC_SEL_CL2 = 0x95;
constexpr uint8_t PICC_SEL_CL3 = 0x97;
constexpr uint8_t PICC_MF_READ  = 0x30;
constexpr uint8_t PICC_MF_WRITE = 0xA0;

// Cascade tag: when a UID is longer than 4 bytes, the first byte of a cascade
// level is this marker rather than UID data.
constexpr uint8_t kCascadeTag = 0x88;

constexpr uint8_t ERR_MASK_SERIOUS = 0x13;  // BufferOvfl | ParityErr | ProtocolErr

}  // namespace

const char* readerStatusName(ReaderStatus s) {
    switch (s) {
        case ReaderStatus::Ok:             return "ok";
        case ReaderStatus::NoCard:         return "no card";
        case ReaderStatus::Timeout:        return "timeout";
        case ReaderStatus::CollisionError: return "collision";
        case ReaderStatus::ChecksumError:  return "bad checksum";
        case ReaderStatus::ProtocolError:  return "protocol error";
        case ReaderStatus::NotPresent:     return "reader not present";
    }
    return "?";
}

// ---- register plumbing ------------------------------------------------------

bool Rfid2::readReg(uint8_t reg, uint8_t& value) const {
    if (!bus_) return false;
    return bus_->readRegister(address_, reg, &value, 1, kI2cFreq);
}

bool Rfid2::readRegs(uint8_t reg, uint8_t* out, size_t len) const {
    if (!bus_) return false;
    return bus_->readRegister(address_, reg, out, len, kI2cFreq);
}

bool Rfid2::writeReg(uint8_t reg, uint8_t value) const {
    if (!bus_) return false;
    return bus_->writeRegister8(address_, reg, value, kI2cFreq);
}

bool Rfid2::setRegBits(uint8_t reg, uint8_t mask) const {
    uint8_t v = 0;
    if (!readReg(reg, v)) return false;
    return writeReg(reg, static_cast<uint8_t>(v | mask));
}

bool Rfid2::clearRegBits(uint8_t reg, uint8_t mask) const {
    uint8_t v = 0;
    if (!readReg(reg, v)) return false;
    return writeReg(reg, static_cast<uint8_t>(v & ~mask));
}

// ---- bring-up ---------------------------------------------------------------

bool Rfid2::begin(m5::I2C_Class* bus, uint8_t i2cAddress) {
    bus_       = bus;
    address_   = i2cAddress;
    present_   = false;
    lastError_ = "";
    if (bus_ == nullptr) {
        lastError_ = "no bus given";
        return false;
    }

    if (!writeReg(REG_COMMAND, CMD_SOFT_RESET)) {
        lastError_ = "no reader on the bus";
        return false;
    }

    // The reset takes a moment and the chip does not answer meaningfully until
    // it finishes. Poll rather than guess at a delay.
    for (int i = 0; i < 20; i++) {
        delay(3);
        uint8_t cmd = 0;
        if (readReg(REG_COMMAND, cmd) && (cmd & (1 << 4)) == 0) break;
    }

    // Timer: prescaler 0xA9 with TAuto gives ~40 kHz, and a reload of 0x03E8
    // makes each transceive time out after about 25 ms. Long enough for the
    // slowest card, short enough that a missing card does not stall the UI.
    writeReg(REG_T_MODE, 0x80);
    writeReg(REG_T_PRESCALER, 0xA9);
    writeReg(REG_T_RELOAD_H, 0x03);
    writeReg(REG_T_RELOAD_L, 0xE8);

    writeReg(REG_TX_ASK, 0x40);  // force 100% ASK
    writeReg(REG_MODE, 0x3D);    // CRC preset 0x6363

    if (!readReg(REG_VERSION, version_)) {
        lastError_ = "cannot read version register";
        return false;
    }
    // 0x00 and 0xFF both mean "nothing is really answering".
    if (version_ == 0x00 || version_ == 0xFF) {
        lastError_ = "reader did not identify itself";
        return false;
    }

    antennaOn();
    present_ = true;
    return true;
}

void Rfid2::antennaOn() { setRegBits(REG_TX_CONTROL, 0x03); }
void Rfid2::antennaOff() { clearRegBits(REG_TX_CONTROL, 0x03); }

// ---- transceive -------------------------------------------------------------

ReaderStatus Rfid2::transceive(const uint8_t* tx, uint8_t txLen, uint8_t txLastBits,
                               uint8_t* rx, uint8_t& rxLen, uint8_t* rxLastBits,
                               bool checkCrc) {
    const uint8_t rxCapacity = rxLen;
    rxLen = 0;

    writeReg(REG_COMMAND, CMD_IDLE);
    writeReg(REG_COM_IRQ, 0x7F);        // clear all interrupt flags
    writeReg(REG_FIFO_LEVEL, 0x80);     // flush the FIFO

    for (uint8_t i = 0; i < txLen; i++) writeReg(REG_FIFO_DATA, tx[i]);

    writeReg(REG_BIT_FRAMING, static_cast<uint8_t>(txLastBits & 0x07));
    writeReg(REG_COMMAND, CMD_TRANSCEIVE);
    setRegBits(REG_BIT_FRAMING, 0x80);  // StartSend

    // Wait for receive-complete, idle, or the chip's own timer. The hardware
    // timer is the real timeout; the loop counter only stops us hanging if the
    // reader stops answering the bus entirely.
    uint8_t irq = 0;
    bool done = false;
    for (int i = 0; i < 400; i++) {
        if (!readReg(REG_COM_IRQ, irq)) {
            clearRegBits(REG_BIT_FRAMING, 0x80);
            lastError_ = "bus went away mid-transceive";
            return ReaderStatus::NotPresent;
        }
        if (irq & 0x30) { done = true; break; }   // RxIRq | IdleIRq
        if (irq & 0x01) {                          // TimerIRq: no card answered
            clearRegBits(REG_BIT_FRAMING, 0x80);
            return ReaderStatus::NoCard;
        }
        delayMicroseconds(150);
    }
    clearRegBits(REG_BIT_FRAMING, 0x80);
    if (!done) return ReaderStatus::Timeout;

    uint8_t err = 0;
    readReg(REG_ERROR, err);
    if (err & ERR_MASK_SERIOUS) return ReaderStatus::ProtocolError;

    uint8_t available = 0;
    if (!readReg(REG_FIFO_LEVEL, available)) return ReaderStatus::NotPresent;

    // A card controls this length. Refuse anything that will not fit rather
    // than trusting it -- this is the bounds check that matters in this file.
    if (available > rxCapacity) {
        lastError_ = "card returned more than we asked for";
        return ReaderStatus::ProtocolError;
    }

    if (available > 0 && !readRegs(REG_FIFO_DATA, rx, available))
        return ReaderStatus::NotPresent;
    rxLen = available;

    uint8_t control = 0;
    readReg(REG_CONTROL, control);
    if (rxLastBits) *rxLastBits = static_cast<uint8_t>(control & 0x07);

    if (err & 0x08) return ReaderStatus::CollisionError;

    if (checkCrc) {
        if (rxLen < 3) return ReaderStatus::ChecksumError;
        uint8_t crc[2];
        if (!calculateCrc(rx, static_cast<uint8_t>(rxLen - 2), crc))
            return ReaderStatus::ProtocolError;
        if (crc[0] != rx[rxLen - 2] || crc[1] != rx[rxLen - 1])
            return ReaderStatus::ChecksumError;
    }

    return ReaderStatus::Ok;
}

bool Rfid2::calculateCrc(const uint8_t* data, uint8_t len, uint8_t out[2]) {
    writeReg(REG_COMMAND, CMD_IDLE);
    writeReg(REG_COM_IRQ, 0x04);     // clear CRCIRq
    writeReg(REG_FIFO_LEVEL, 0x80);
    for (uint8_t i = 0; i < len; i++) writeReg(REG_FIFO_DATA, data[i]);
    writeReg(REG_COMMAND, CMD_CALC_CRC);

    for (int i = 0; i < 200; i++) {
        uint8_t irq = 0;
        if (!readReg(0x05, irq)) return false;  // DivIrqReg
        if (irq & 0x04) {
            writeReg(REG_COMMAND, CMD_IDLE);
            return readReg(REG_CRC_RESULT_L, out[0]) &&
                   readReg(REG_CRC_RESULT_H, out[1]);
        }
        delayMicroseconds(100);
    }
    writeReg(REG_COMMAND, CMD_IDLE);
    return false;
}

// ---- the ISO14443-A dance ---------------------------------------------------

ReaderStatus Rfid2::requestA(uint16_t& atqa) {
    writeReg(REG_COLL, 0x80);  // clear ValuesAfterColl

    uint8_t cmd = PICC_REQA;
    uint8_t rx[4] = {0};
    uint8_t rxLen = sizeof(rx);

    // REQA is a 7-bit frame, not 8. Getting this wrong means no card ever
    // answers and the reader looks broken.
    const ReaderStatus st = transceive(&cmd, 1, 7, rx, rxLen, nullptr);
    if (st != ReaderStatus::Ok) return st;
    if (rxLen != 2) return ReaderStatus::ProtocolError;

    atqa = static_cast<uint16_t>(rx[0] | (rx[1] << 8));
    return ReaderStatus::Ok;
}

ReaderStatus Rfid2::cascade(credential::TagIdentity& tag) {
    static const uint8_t kSelCmd[3] = {PICC_SEL_CL1, PICC_SEL_CL2, PICC_SEL_CL3};

    tag.uidLen = 0;

    for (uint8_t level = 0; level < 3; level++) {
        // Anticollision: SEL, NVB=0x20, and the card answers with 4 UID bytes
        // plus a BCC.
        const uint8_t tx[2] = {kSelCmd[level], 0x20};
        uint8_t rx[8] = {0};
        uint8_t rxLen = sizeof(rx);

        ReaderStatus st = transceive(tx, 2, 0, rx, rxLen, nullptr);
        if (st != ReaderStatus::Ok) return st;
        if (rxLen != 5) return ReaderStatus::ProtocolError;

        // The card's own integrity check. If this fails we are reading noise,
        // and reporting a UID from it would be worse than reporting nothing.
        const uint8_t bcc = rx[0] ^ rx[1] ^ rx[2] ^ rx[3];
        if (bcc != rx[4]) return ReaderStatus::ChecksumError;

        // SELECT: SEL, NVB=0x70, the five bytes back, then CRC.
        uint8_t sel[9] = {kSelCmd[level], 0x70, rx[0], rx[1], rx[2], rx[3], rx[4], 0, 0};
        if (!calculateCrc(sel, 7, &sel[7])) return ReaderStatus::ProtocolError;

        uint8_t sak[8] = {0};
        uint8_t sakLen = sizeof(sak);
        st = transceive(sel, 9, 0, sak, sakLen, nullptr, /*checkCrc=*/true);
        if (st != ReaderStatus::Ok) return st;
        if (sakLen != 3) return ReaderStatus::ProtocolError;

        const bool more = (sak[0] & 0x04) != 0;

        // On a cascading level the first byte is the cascade tag, not UID.
        const uint8_t first = more ? 1 : 0;
        const uint8_t take  = static_cast<uint8_t>(4 - first);
        if (more && rx[0] != kCascadeTag) return ReaderStatus::ProtocolError;
        if (tag.uidLen + take > kMaxUidLen) return ReaderStatus::ProtocolError;

        std::memcpy(tag.uid + tag.uidLen, rx + first, take);
        tag.uidLen = static_cast<uint8_t>(tag.uidLen + take);

        if (!more) {
            tag.sak = sak[0];
            return ReaderStatus::Ok;
        }
    }
    return ReaderStatus::ProtocolError;
}

ReaderStatus Rfid2::requestAts(credential::TagIdentity& tag) {
    // RATS: E0 50 (FSDI=5 => 64 byte frames, CID 0), then CRC.
    uint8_t tx[4] = {PICC_RATS, 0x50, 0, 0};
    if (!calculateCrc(tx, 2, &tx[2])) return ReaderStatus::ProtocolError;

    uint8_t rx[kMaxAtsLen + 4] = {0};
    uint8_t rxLen = sizeof(rx);
    const ReaderStatus st = transceive(tx, 4, 0, rx, rxLen, nullptr, /*checkCrc=*/true);
    if (st != ReaderStatus::Ok) return st;
    if (rxLen < 3) return ReaderStatus::ProtocolError;

    // rx[0] is TL, the length of the ATS including itself, and the last two
    // bytes are CRC. Trust the frame length we measured over the card's claim.
    uint8_t atsLen = static_cast<uint8_t>(rxLen - 2);
    if (atsLen > kMaxAtsLen) atsLen = kMaxAtsLen;

    std::memcpy(tag.ats, rx, atsLen);
    tag.atsLen = atsLen;
    return ReaderStatus::Ok;
}

ReaderStatus Rfid2::poll(credential::TagIdentity& tag) {
    if (!present_) return ReaderStatus::NotPresent;

    credential::TagIdentity found;

    uint16_t atqa = 0;
    ReaderStatus st = requestA(atqa);
    if (st != ReaderStatus::Ok) return st;
    found.atqa = atqa;

    st = cascade(found);
    if (st != ReaderStatus::Ok) return st;

    // ISO-DEP cards can be asked for an ATS, which is what distinguishes a
    // DESFire from an unidentifiable ISO-DEP card. A card refusing RATS is not
    // an error -- it just means we learn less.
    if (found.isIso14443_4()) requestAts(found);

    tag = found;
    return ReaderStatus::Ok;
}

// Crypto1 authentication is performed by the reader itself: we hand it the
// key and the UID and it runs the three-pass handshake in hardware.
ReaderStatus Rfid2::authenticate(uint8_t keyType, uint8_t block,
                                 const uint8_t key[6],
                                 const credential::TagIdentity& tag) {
    // Mifare Classic authenticates against four UID bytes. Cards with a 7-byte
    // UID use the LAST four, which is the detail that silently breaks auth on
    // anything that is not a plain 1K.
    const uint8_t* uid = tag.uid;
    if (tag.uidLen >= 7) uid = tag.uid + (tag.uidLen - 4);
    else if (tag.uidLen < 4) return ReaderStatus::ProtocolError;

    uint8_t buf[12];
    buf[0] = keyType;   // 0x60 key A, 0x61 key B
    buf[1] = block;
    for (uint8_t i = 0; i < 6; i++) buf[2 + i] = key[i];
    for (uint8_t i = 0; i < 4; i++) buf[8 + i] = uid[i];

    writeReg(REG_COMMAND, CMD_IDLE);
    writeReg(REG_COM_IRQ, 0x7F);
    writeReg(REG_FIFO_LEVEL, 0x80);
    for (uint8_t i = 0; i < sizeof(buf); i++) writeReg(REG_FIFO_DATA, buf[i]);
    writeReg(REG_COMMAND, CMD_MF_AUTHENT);

    // MFAuthent signals completion through IdleIRq; there is no RxIRq for it.
    for (int i = 0; i < 300; i++) {
        uint8_t irq = 0;
        if (!readReg(REG_COM_IRQ, irq)) return ReaderStatus::NotPresent;
        if (irq & 0x10) break;                       // IdleIRq: sequence finished
        if (irq & 0x01) return ReaderStatus::NoCard;  // TimerIRq
        delayMicroseconds(150);
    }

    // The only trustworthy success signal is the crypto unit actually being on.
    uint8_t status2 = 0;
    if (!readReg(REG_STATUS2, status2)) return ReaderStatus::NotPresent;
    return (status2 & 0x08) ? ReaderStatus::Ok : ReaderStatus::ProtocolError;
}

void Rfid2::stopCrypto1() {
    // Leaving the crypto unit on makes every later plain command fail in a way
    // that looks like a dead card.
    clearRegBits(REG_STATUS2, 0x08);
}

ReaderStatus Rfid2::reselect(credential::TagIdentity& tag) {
    uint16_t atqa = 0;
    ReaderStatus st = requestA(atqa);
    if (st != ReaderStatus::Ok) return st;
    return cascade(tag);
}

uint16_t Rfid2::probeAttemptCount() {
    return static_cast<uint16_t>(credential::defaultKeyCount() * 2);
}

bool Rfid2::probeDefaultKeys(credential::TagIdentity& tag, uint8_t* keyIndexOut,
                             uint8_t* keyTypeOut) {
    tag.triedDefaultKeys   = true;
    tag.defaultKeyAccepted = false;
    lastProbeSawCard_      = false;
    if (!present_) return false;

    // Only Crypto1 cards have keys to try. Running this against a DESFire would
    // be noise, and reporting a failure against it would be misleading.
    if (!tag.isClassicCompatible()) return false;

    const credential::DefaultKey* keys = credential::defaultKeys();
    const size_t n = credential::defaultKeyCount();

    for (uint8_t type = 0; type < 2; type++) {
        const uint8_t cmd = type == 0 ? PICC_AUTH_KEY_A : PICC_AUTH_KEY_B;
        for (size_t i = 0; i < n; i++) {
            // A failed authentication leaves the card mute, so it has to be
            // taken through anticollision again before the next attempt.
            credential::TagIdentity again;
            if (reselect(again) != ReaderStatus::Ok) {
                stopCrypto1();
                delay(5);
                continue;
            }
            lastProbeSawCard_ = true;

            if (authenticate(cmd, /*block=*/0, keys[i].key, again) == ReaderStatus::Ok) {
                stopCrypto1();
                tag.defaultKeyAccepted = true;
                tag.defaultKeySector   = 0;
                if (keyIndexOut) *keyIndexOut = static_cast<uint8_t>(i);
                if (keyTypeOut)  *keyTypeOut  = type;
                return true;
            }
            stopCrypto1();
        }
    }
    return false;
}

// ---- sector-level access -----------------------------------------------------

uint8_t Rfid2::sectorCount(uint8_t sak) {
    // SAK bits 3 and 4 carry the size for Crypto1 cards. Mini is a 1K SAK with
    // a smaller memory, and there is no way to tell it apart from a 1K without
    // reading past its end -- so it is treated as 1K and the read simply fails
    // on the sectors that are not there, which is reported rather than hidden.
    if ((sak & 0x08) == 0) return 0;      // not Crypto1 at all
    if (sak & 0x10) return 40;            // 4K
    return 16;                            // 1K
}

uint8_t Rfid2::blocksInSector(uint8_t sector) {
    // The first 32 sectors of a 4K card hold four blocks; the last eight hold
    // sixteen. Assuming four everywhere reads the wrong blocks for the whole
    // top third of a 4K badge.
    return sector < 32 ? 4 : 16;
}

uint8_t Rfid2::firstBlockOfSector(uint8_t sector) {
    if (sector < 32) return static_cast<uint8_t>(sector * 4);
    return static_cast<uint8_t>(128 + (sector - 32) * 16);
}

bool Rfid2::openSector(uint8_t sector, const credential::TagIdentity& tag,
                       uint8_t* keyIndexOut, uint8_t* keyTypeOut) {
    if (!present_) return false;
    if (!tag.isClassicCompatible()) return false;

    const credential::DefaultKey* keys = credential::defaultKeys();
    const size_t n = credential::defaultKeyCount();
    const uint8_t block = firstBlockOfSector(sector);

    for (uint8_t type = 0; type < 2; type++) {
        const uint8_t cmd = type == 0 ? PICC_AUTH_KEY_A : PICC_AUTH_KEY_B;
        for (size_t i = 0; i < n; i++) {
            // A failed authentication leaves the card mute, so it has to be
            // taken back through anticollision before the next attempt. This
            // is why a full sweep is slow, and why the screen shows progress
            // rather than appearing to hang.
            credential::TagIdentity again;
            if (reselect(again) != ReaderStatus::Ok) {
                stopCrypto1();
                delay(5);
                continue;
            }

            if (authenticate(cmd, block, keys[i].key, again) == ReaderStatus::Ok) {
                // Crypto1 deliberately left running: the caller reads the
                // sector's blocks now or not at all.
                if (keyIndexOut) *keyIndexOut = static_cast<uint8_t>(i);
                if (keyTypeOut)  *keyTypeOut  = type;
                return true;
            }
            stopCrypto1();
        }
    }
    return false;
}

ReaderStatus Rfid2::readBlock(uint8_t block, uint8_t out[16]) {
    if (!present_) return ReaderStatus::NotPresent;

    uint8_t tx[4] = {PICC_MF_READ, block, 0, 0};
    if (!calculateCrc(tx, 2, &tx[2])) return ReaderStatus::ProtocolError;

    uint8_t rx[18] = {0};
    uint8_t rxLen  = sizeof(rx);
    const ReaderStatus st =
        transceive(tx, 4, 0, rx, rxLen, nullptr, /*checkCrc=*/true);
    if (st != ReaderStatus::Ok) return st;

    // A short answer is a NAK or a truncated frame, not sixteen bytes of data.
    // Copying it anyway would put whatever was already in the buffer into a
    // dump the operator hands to a client.
    if (rxLen < 18) return ReaderStatus::ProtocolError;

    std::memcpy(out, rx, 16);
    return ReaderStatus::Ok;
}

void Rfid2::endSector() {
    stopCrypto1();
    halt();
}

// ---- writing -----------------------------------------------------------------

bool Rfid2::magicUnlock() {
    if (!present_) return false;

    // The Gen1a backdoor: a 7-bit 0x40, then a full 0x43. A card that answers
    // 0x0A to both allows block 0 to be written without authenticating. A
    // normal card does not answer at all, which is exactly what makes this a
    // safe way to tell a blank from a real badge before writing anything.
    halt();
    delay(5);

    uint8_t rx[4] = {0};
    uint8_t rxLen = sizeof(rx);
    uint8_t cmd = 0x40;
    // 7 bits, not 8. The short frame is the whole trick.
    if (transceive(&cmd, 1, 7, rx, rxLen, nullptr) != ReaderStatus::Ok) return false;
    if (rxLen < 1 || (rx[0] & 0x0F) != 0x0A) return false;

    cmd   = 0x43;
    rxLen = sizeof(rx);
    if (transceive(&cmd, 1, 0, rx, rxLen, nullptr) != ReaderStatus::Ok) return false;
    if (rxLen < 1 || (rx[0] & 0x0F) != 0x0A) return false;

    return true;
}

ReaderStatus Rfid2::writeBlock(uint8_t block, const uint8_t data[16],
                               bool allowManufacturerBlock) {
    if (!present_) return ReaderStatus::NotPresent;
    if (data == nullptr) return ReaderStatus::ProtocolError;

    // Block 0 is read-only on a normal card, and a failed write there is how
    // people brick badges. It takes a deliberate flag, set only when the card
    // has already answered the magic backdoor.
    if (block == 0 && !allowManufacturerBlock) return ReaderStatus::ProtocolError;

    // MIFARE WRITE is two stages: the command and block number, then -- after
    // the card has acknowledged -- the sixteen bytes.
    uint8_t tx[4] = {PICC_MF_WRITE, block, 0, 0};
    if (!calculateCrc(tx, 2, &tx[2])) return ReaderStatus::ProtocolError;

    uint8_t rx[4] = {0};
    uint8_t rxLen = sizeof(rx);
    ReaderStatus st = transceive(tx, 4, 0, rx, rxLen, nullptr);
    if (st != ReaderStatus::Ok) return st;
    // The card answers with a 4 bit ACK. Anything else is a NAK, and continuing
    // would push sixteen bytes at a card that already said no.
    if (rxLen < 1 || (rx[0] & 0x0F) != 0x0A) return ReaderStatus::ProtocolError;

    uint8_t payload[18];
    std::memcpy(payload, data, 16);
    if (!calculateCrc(payload, 16, &payload[16])) return ReaderStatus::ProtocolError;

    rxLen = sizeof(rx);
    st = transceive(payload, 18, 0, rx, rxLen, nullptr);
    if (st != ReaderStatus::Ok) return st;
    if (rxLen < 1 || (rx[0] & 0x0F) != 0x0A) return ReaderStatus::ProtocolError;

    return ReaderStatus::Ok;
}

// ---- the shared reader -------------------------------------------------------

Rfid2& sharedReader() {
    static Rfid2 instance;
    return instance;
}

bool openSharedReader(const char** busNameOut) {
    static const char* busName = "none";

    Rfid2& r = sharedReader();
    if (r.present()) {
        if (busNameOut) *busNameOut = busName;
        return true;
    }

    // The reader can be on either port. Try the board's own Port A first, then
    // the cap's pass-through. Confirmed on hardware: with both units fitted the
    // NFC Universal sits at 0x50 on Port A and the RFID2 at 0x28 on the cap.
    M5.Ex_I2C.begin(I2C_NUM_0, board::kGroveSda, board::kGroveScl);

    if (r.begin(&M5.Ex_I2C)) {
        busName = "Port A";
    } else if (r.begin(&M5.In_I2C)) {
        busName = "cap";
    } else {
        busName = "none";
    }

    if (busNameOut) *busNameOut = busName;
    return r.present();
}

void Rfid2::halt() {
    uint8_t tx[4] = {PICC_HLTA, 0x00, 0, 0};
    if (!calculateCrc(tx, 2, &tx[2])) return;

    // A card that accepts HLTA answers with nothing at all, so a timeout here
    // is success and anything else is not worth reporting.
    uint8_t rx[4];
    uint8_t rxLen = sizeof(rx);
    transceive(tx, 4, 0, rx, rxLen, nullptr);
}

}  // namespace orthrus::hal
