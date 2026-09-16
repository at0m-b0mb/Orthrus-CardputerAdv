#include "lora_radio.h"

#include <Arduino.h>
#include <SPI.h>

#include "board.h"

namespace orthrus::hal {
namespace {

namespace bd = orthrus::board;

// The radio shares this bus with the microSD card. Verified on hardware: the
// radio still answers after the SD driver has driven the bus, provided each
// side owns its own chip select.
SPIClass g_spi(FSPI);

Module g_module(bd::kLoraCs, bd::kLoraDio1, bd::kLoraRst, bd::kLoraBusy, g_spi);
SX1262 g_radio(&g_module);

volatile bool g_packetWaiting = false;

// Kept tiny and in IRAM: it runs from the DIO1 interrupt.
void IRAM_ATTR onDio1() { g_packetWaiting = true; }

// LoRaWAN public-network sync word. Private networks use 0x12; using the wrong
// one means the modem never declares a valid header and the scanner looks
// broken rather than empty.
constexpr uint8_t kSyncWordPublic = 0x34;

}  // namespace

bool LoraRadio::begin() {
    g_spi.begin(bd::kLoraSck, bd::kLoraMiso, bd::kLoraMosi, bd::kLoraCs);

    // Deliberately not RadioLib's defaults:
    //  - TCXO at 1.8 V on DIO3. This module carries a TCXO and RadioLib assumes
    //    1.6 V, which leaves the reference marginal.
    //  - useRegulatorLDO = false, i.e. DC-DC, matching the module design.
    const int st = g_radio.begin(
        static_cast<float>(cfg_.freqHz) / 1e6f,
        static_cast<float>(cfg_.bwKhz),
        cfg_.sf,
        cfg_.cr,
        kSyncWordPublic,
        /*power=*/-9,          // lowest legal setting; we do not transmit
        /*preambleLength=*/8,  // LoRaWAN uplink preamble
        bd::kLoraTcxoVolts,
        /*useRegulatorLDO=*/false);

    if (st != RADIOLIB_ERR_NONE) {
        lastError_ = "radio begin failed";
        ready_     = false;
        return false;
    }

    // No separate RX/TX enable lines on this cap, so DIO2 drives the RF switch.
    // Without this the front end is not switched into the receive path.
    if (bd::kLoraDio2AsRfSwitch) {
        const int sw = g_radio.setDio2AsRfSwitch(true);
        if (sw != RADIOLIB_ERR_NONE) {
            lastError_ = "DIO2 RF switch failed";
            ready_     = false;
            return false;
        }
    }

    // LoRaWAN uses an explicit header and CRC on uplinks.
    g_radio.setCRC(true);
    g_radio.explicitHeader();

    g_radio.setPacketReceivedAction(onDio1);

    ready_     = true;
    lastError_ = "";
    return true;
}

bool LoraRadio::configure(const RadioConfig& cfg) {
    if (!ready_) return false;

    // Order matters: the image calibration RadioLib performs on setFrequency is
    // band-dependent, so frequency goes first.
    if (g_radio.setFrequency(static_cast<float>(cfg.freqHz) / 1e6f) !=
        RADIOLIB_ERR_NONE) {
        lastError_ = "bad frequency";
        return false;
    }
    if (g_radio.setBandwidth(static_cast<float>(cfg.bwKhz)) != RADIOLIB_ERR_NONE) {
        lastError_ = "bad bandwidth";
        return false;
    }
    if (g_radio.setSpreadingFactor(cfg.sf) != RADIOLIB_ERR_NONE) {
        lastError_ = "bad spreading factor";
        return false;
    }
    if (g_radio.setCodingRate(cfg.cr) != RADIOLIB_ERR_NONE) {
        lastError_ = "bad coding rate";
        return false;
    }

    cfg_       = cfg;
    lastError_ = "";
    return true;
}

bool LoraRadio::listen() {
    if (!ready_) return false;
    g_packetWaiting = false;
    const int st = g_radio.startReceive();
    if (st != RADIOLIB_ERR_NONE) {
        lastError_ = "startReceive failed";
        return false;
    }
    return true;
}

int LoraRadio::poll(uint8_t* buf, size_t cap, lorawan::RxMeta& meta) {
    if (!ready_ || !g_packetWaiting) return 0;
    g_packetWaiting = false;

    const size_t len = g_radio.getPacketLength();

    // Capture the radio-side facts before restarting receive: they belong to
    // the packet just read, and startReceive() invalidates them.
    meta.freqHz  = cfg_.freqHz;
    meta.sf      = cfg_.sf;
    meta.bwKhz   = cfg_.bwKhz;
    meta.rssiDbm = static_cast<int16_t>(g_radio.getRSSI());
    meta.snrDb   = static_cast<int8_t>(g_radio.getSNR());
    meta.timeMs  = millis();

    if (len > cap) {
        stats_.tooLong++;
        g_radio.startReceive();
        return -1;
    }

    const int st = g_radio.readData(buf, len);
    g_radio.startReceive();

    if (st == RADIOLIB_ERR_CRC_MISMATCH) {
        // Heard a LoRa frame that failed CRC. Worth counting: it means the band
        // is live and we are simply too far away or on the wrong SF.
        stats_.crcErrors++;
        return -1;
    }
    if (st != RADIOLIB_ERR_NONE) {
        stats_.otherErrors++;
        return -1;
    }

    stats_.packets++;
    return static_cast<int>(len);
}

float LoraRadio::instantRssi() {
    if (!ready_) return 0.0f;
    return g_radio.getRSSI(false);
}

}  // namespace orthrus::hal
