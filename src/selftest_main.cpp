// On-device self-test.
//
// The host tests prove the engine's logic. They cannot prove the ESP32 build of
// that engine behaves the same way, that the radio really retunes when told to,
// or that the radio and the SD card survive sharing one SPI bus under load.
// Those are target questions and they need target answers.
//
// Built as its own environment so it never ships inside the product:
//     pio run -e selftest -t upload
//
// Results go to USB serial and to the panel, so it is usable with no host.

#include <M5Cardputer.h>
#include <RadioLib.h>
#include <SD.h>
#include <SPI.h>
#include <TinyGPSPlus.h>

#include <cstdio>

#include "hal/board.h"
#include "lorawan/census.h"
#include "lorawan/findings.h"
#include "lorawan/payload.h"
#include "lorawan/phy.h"
#include "lorawan/region.h"

namespace bd = orthrus::board;
using namespace orthrus::lorawan;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* what) {
    if (ok) {
        g_pass++;
        Serial.printf("  [ok]   %s\n", what);
    } else {
        g_fail++;
        Serial.printf("  [FAIL] %s\n", what);
    }
}

void banner(const char* s) {
    Serial.println();
    Serial.printf("== %s ==\n", s);
}

// ---------------------------------------------------------------------------
// 1. Engine parity: does the target build agree with the host build?
//
// Different compiler, different word sizes for the fast integer types,
// different struct packing. These are the same judgements the host suite makes;
// if any of them disagrees here, something is different about the target and we
// need to know before trusting a finding made in the field.
// ---------------------------------------------------------------------------

void pushU16LE(uint8_t*& p, uint16_t v) { *p++ = v & 0xFF; *p++ = v >> 8; }
void pushU32LE(uint8_t*& p, uint32_t v) {
    *p++ = v & 0xFF; *p++ = (v >> 8) & 0xFF; *p++ = (v >> 16) & 0xFF; *p++ = (v >> 24) & 0xFF;
}

void testEngineParity() {
    banner("engine parity (target build)");

    // A well-formed uplink must parse with the fields we expect.
    uint8_t buf[64];
    uint8_t* p = buf;
    *p++ = 0x40;
    pushU32LE(p, 0x26011BDA);
    *p++ = 0x80;            // ADR set, no FOpts
    pushU16LE(p, 0x0005);
    *p++ = 0x02;            // FPort
    *p++ = 0xAA; *p++ = 0xBB; *p++ = 0xCC;
    pushU32LE(p, 0x11223344);

    Frame f;
    check(parse(buf, static_cast<size_t>(p - buf), f), "uplink parses");
    check(f.data.devAddr == 0x26011BDA, "DevAddr little-endian decode");
    check(f.data.fCnt == 5, "FCnt decode");
    check(f.data.adr, "ADR flag");
    check(f.data.frmPayloadLen == 3, "FRMPayload length");

    // The hostile case: FOptsLen lying about how much it carries.
    uint8_t bad[16];
    uint8_t* q = bad;
    *q++ = 0x40;
    pushU32LE(q, 0xDEADBEEF);
    *q++ = 0x0F;            // claims 15 bytes of FOpts that are not there
    pushU16LE(q, 1);
    pushU32LE(q, 0);
    Frame bf;
    check(!parse(bad, static_cast<size_t>(q - bad), bf), "FOptsLen overrun rejected");
    check(bf.error == ParseError::FOptsOverrun, "overrun reported as such");

    // Payload honesty: short printable runs must not be called plaintext.
    const uint8_t two[2] = {'O', 'K'};
    check(!inspectPayload(two, 2).looksPlaintext(), "2-byte payload not called plaintext");
    const char* js = "{\"t\":21.5}";
    check(inspectPayload(reinterpret_cast<const uint8_t*>(js), 10).confidence == 97,
          "JSON cleartext scored 97");

    // The counter-direction fix, checked on target.
    //
    // static, not a local: sizeof(Census) is ~17 KB and the Arduino loopTask
    // stack is 8 KB. Declaring one as a local overflows the stack instantly --
    // which is exactly what the first run of this self-test did.
    static Census c;
    RxMeta m; m.freqHz = 868100000; m.sf = 7; m.bwKhz = 125; m.rssiDbm = -90; m.snrDb = 7;
    uint16_t u = 500, dn = 10;
    for (int i = 0; i < 10; i++) {
        Frame up; up.mtype = MType::UnconfirmedDataUp; up.data.devAddr = 0x1234;
        up.data.fCnt = u++; up.data.adr = true; up.data.hasFPort = true; up.data.fPort = 1;
        m.timeMs += 1000; c.observe(up, m);

        Frame dw; dw.mtype = MType::UnconfirmedDataDown; dw.data.devAddr = 0x1234;
        dw.data.fCnt = dn++; dw.data.adr = true; dw.data.hasFPort = true; dw.data.fPort = 1;
        m.timeMs += 500; c.observe(dw, m);
    }
    check(c.at(0).up.resets == 0 && c.at(0).down.resets == 0,
          "bidirectional traffic produces no false resets");

    CaptureContext ctx;
    ctx.listenedMs = 60000; ctx.channelsCovered = 8; ctx.channelsInRegion = 8;
    ctx.sfCovered = 6; ctx.sfInRegion = 6;
    const auto a = assess(c.at(0), ctx);
    check(a.grade == Grade::APlus, "healthy device grades A+ on target");
    check(ctx.coveragePercent() == 100, "coverage arithmetic");

    CaptureContext one;
    one.listenedMs = 60000; one.channelsCovered = 1; one.channelsInRegion = 8;
    one.sfCovered = 1; one.sfInRegion = 6;
    check(one.coveragePercent() == 2, "single-radio coverage is 2 percent");

    // Memory footprint of the census, measured rather than assumed.
    Serial.printf("  [info] sizeof(DeviceRecord)=%u  Census=%u bytes\n",
                  static_cast<unsigned>(sizeof(DeviceRecord)),
                  static_cast<unsigned>(sizeof(Census)));
}

// ---------------------------------------------------------------------------
// 2. Radio: does it really retune?
//
// A radio that silently ignores SetFrequency looks identical to one that works,
// right up until the census is empty and nobody knows why. Sweeping the whole
// sub-GHz range and printing the noise profile answers it: a working receiver
// shows a frequency-dependent floor with structure, a broken one shows a flat
// line.
// ---------------------------------------------------------------------------

SPIClass g_spi(FSPI);
Module   g_mod(bd::kLoraCs, bd::kLoraDio1, bd::kLoraRst, bd::kLoraBusy, g_spi);
SX1262   g_radio(&g_mod);
bool     g_radioUp = false;

void testRadioBringUp() {
    banner("radio bring-up");
    g_spi.begin(bd::kLoraSck, bd::kLoraMiso, bd::kLoraMosi, bd::kLoraCs);

    const int st = g_radio.begin(868.1, 125.0, 7, 5, 0x34, -9, 8,
                                 bd::kLoraTcxoVolts, false);
    check(st == RADIOLIB_ERR_NONE, "SX1262 begin()");
    if (st != RADIOLIB_ERR_NONE) {
        Serial.printf("  [info] begin() = %d (-2 means chip not found)\n", st);
        return;
    }
    check(g_radio.setDio2AsRfSwitch(true) == RADIOLIB_ERR_NONE, "DIO2 as RF switch");
    g_radio.setCRC(true);
    g_radio.explicitHeader();
    g_radioUp = true;
}

float floorAt(float mhz, int samples = 12) {
    if (g_radio.standby() != RADIOLIB_ERR_NONE) return 0.0f;
    if (g_radio.setFrequency(mhz) != RADIOLIB_ERR_NONE) return 0.0f;
    g_radio.startReceive();
    delay(25);
    float sum = 0;
    for (int i = 0; i < samples; i++) { sum += g_radio.getRSSI(false); delay(3); }
    return sum / samples;
}

void testRadioSweep() {
    banner("radio sweep 863-930 MHz");
    if (!g_radioUp) { Serial.println("  [skip] radio not up"); return; }

    constexpr float kStart = 863.0f, kEnd = 930.0f, kStep = 1.0f;
    float lo = 999, hi = -999, sum = 0;
    int   n = 0;

    for (float mhz = kStart; mhz <= kEnd; mhz += kStep) {
        const float v = floorAt(mhz, 8);
        if (v == 0.0f) continue;
        if (v < lo) lo = v;
        if (v > hi) hi = v;
        sum += v; n++;

        // A bar per megahertz: -130 dBm at the left, -60 at the right.
        int bars = static_cast<int>((v + 130.0f) * 40.0f / 70.0f);
        if (bars < 0) bars = 0;
        if (bars > 40) bars = 40;
        char bar[42];
        for (int i = 0; i < bars; i++) bar[i] = '#';
        bar[bars] = '\0';
        Serial.printf("  %6.1f MHz %7.1f dBm %s\n", mhz, v, bar);
    }

    Serial.printf("  [info] %d points, floor %.1f to %.1f dBm, mean %.1f\n",
                  n, lo, hi, n ? sum / n : 0.0f);
    check(n > 60, "swept the whole range");
    // If every point reads identically the synthesiser is not moving, or we are
    // reading a cached register rather than the air.
    check((hi - lo) > 1.5f, "noise floor varies with frequency (radio really retunes)");
}

void testRadioParamChanges() {
    banner("radio parameter changes");
    if (!g_radioUp) { Serial.println("  [skip] radio not up"); return; }

    g_radio.standby();
    check(g_radio.setSpreadingFactor(12) == RADIOLIB_ERR_NONE, "SF12 accepted in standby");
    check(g_radio.setSpreadingFactor(7) == RADIOLIB_ERR_NONE, "SF7 accepted in standby");
    check(g_radio.setBandwidth(250.0) == RADIOLIB_ERR_NONE, "BW250 accepted");
    check(g_radio.setBandwidth(125.0) == RADIOLIB_ERR_NONE, "BW125 restored");
    check(g_radio.setCodingRate(8) == RADIOLIB_ERR_NONE, "CR 4/8 accepted");
    check(g_radio.setCodingRate(5) == RADIOLIB_ERR_NONE, "CR 4/5 restored");
}

// ---------------------------------------------------------------------------
// 3. Shared SPI under load.
//
// The radio and the microSD card share SCK, MOSI and MISO. One quiet handshake
// proved they coexist; this proves they keep coexisting while both are busy,
// which is what a capture-to-card session actually does.
// ---------------------------------------------------------------------------

void testSharedBusStress() {
    banner("shared SPI stress (radio + microSD)");
    if (!g_radioUp) { Serial.println("  [skip] radio not up"); return; }

    const bool sd = SD.begin(bd::kSdCs, g_spi, 20000000);
    if (!sd) {
        Serial.println("  [info] no SD card present, testing radio side only");
    }

    constexpr int kRounds = 150;
    int radioFail = 0, sdFail = 0;

    for (int i = 0; i < kRounds; i++) {
        if (sd) {
            File fh = SD.open("/orthrus_stress.txt", FILE_APPEND);
            if (fh) {
                fh.printf("round %d rssi %.1f\n", i, g_radio.getRSSI(false));
                fh.close();
            } else {
                sdFail++;
            }
        }
        if (g_radio.standby() != RADIOLIB_ERR_NONE) { radioFail++; continue; }
        if (g_radio.setFrequency(868.1f + (i % 5) * 0.2f) != RADIOLIB_ERR_NONE) radioFail++;
        if (g_radio.startReceive() != RADIOLIB_ERR_NONE) radioFail++;
    }

    Serial.printf("  [info] %d rounds, radio errors %d, sd errors %d\n",
                  kRounds, radioFail, sdFail);
    check(radioFail == 0, "radio survives interleaved SD traffic");
    if (sd) {
        check(sdFail == 0, "SD survives interleaved radio traffic");
        SD.remove("/orthrus_stress.txt");
    }
}

// ---------------------------------------------------------------------------
// 4. Leak soak.
//
// The capture loop runs for hours. Anything that leaks a few bytes a frame ends
// the session with a reboot in the middle of an engagement.
// ---------------------------------------------------------------------------

void testHeapSoak() {
    banner("heap soak");

    static Census census;  // see the note in testEngineParity: never a local
    RxMeta m; m.freqHz = 868100000; m.sf = 7; m.bwKhz = 125; m.rssiDbm = -95; m.snrDb = 6;
    CaptureContext ctx;
    ctx.listenedMs = 600000; ctx.channelsCovered = 8; ctx.channelsInRegion = 8;
    ctx.sfCovered = 2; ctx.sfInRegion = 6;

    const uint32_t before = ESP.getFreeHeap();

    for (uint32_t round = 0; round < 40; round++) {
        for (uint32_t i = 0; i < 500; i++) {
            Frame f;
            f.mtype = MType::UnconfirmedDataUp;
            f.data.devAddr = 0x26000000 + (i % 64);
            f.data.fCnt = static_cast<uint16_t>(i);
            f.data.adr = (i & 1) != 0;
            f.data.hasFPort = true;
            f.data.fPort = 1;
            m.timeMs += 10;
            census.observe(f, m);
        }
        for (size_t k = 0; k < census.size(); k++) assess(census.at(k), ctx);
        census.reset();
    }

    const uint32_t after = ESP.getFreeHeap();
    Serial.printf("  [info] heap %u -> %u (delta %ld) over 20000 frames\n",
                  static_cast<unsigned>(before), static_cast<unsigned>(after),
                  static_cast<long>(after) - static_cast<long>(before));
    check(after + 512 >= before, "no heap leak across 20000 frames");
    check(ESP.getMinFreeHeap() > 40000, "minimum free heap stayed healthy");
}

// ---------------------------------------------------------------------------
// 5. Peripherals.
// ---------------------------------------------------------------------------

TinyGPSPlus g_gps;

void testGps() {
    banner("gps");
    Serial2.begin(bd::kGpsBaud, SERIAL_8N1, bd::kGpsRx, bd::kGpsTx);
    delay(50);
    while (Serial2.available()) Serial2.read();

    uint32_t bytes = 0, sentences = 0;
    const uint32_t deadline = millis() + 3000;
    while (millis() < deadline) {
        while (Serial2.available()) {
            const char c = Serial2.read();
            bytes++;
            if (g_gps.encode(c)) sentences++;
        }
    }
    Serial.printf("  [info] %lu bytes, %lu NMEA sentences, %lu sats, fix=%s\n",
                  static_cast<unsigned long>(bytes), static_cast<unsigned long>(sentences),
                  static_cast<unsigned long>(g_gps.satellites.value()),
                  g_gps.location.isValid() ? "yes" : "no");
    check(sentences > 0, "GPS emits valid NMEA");
}

void testI2C() {
    banner("i2c");
    bool found[120] = {false};
    M5.Ex_I2C.begin(I2C_NUM_0, bd::kGroveSda, bd::kGroveScl);
    M5.Ex_I2C.scanID(found);
    int n = 0;
    for (uint8_t a = 0x08; a < 0x78; a++) {
        if (!found[a]) continue;
        n++;
        const char* name = (a == bd::kAddrNfcUniversal) ? "NFC Universal (ST25R3916)"
                         : (a == bd::kAddrRfid2)        ? "RFID2 (WS1850S)"
                                                        : "unknown";
        Serial.printf("  [info] Grove 0x%02X  %s\n", a, name);
    }
    if (n == 0) Serial.println("  [info] no units on Grove Port A");
}

void testPower() {
    banner("power and board");
    Serial.printf("  [info] board=%d battery=%d%% heap=%u psram=%u\n",
                  static_cast<int>(M5.getBoard()), M5.Power.getBatteryLevel(),
                  static_cast<unsigned>(ESP.getFreeHeap()),
                  static_cast<unsigned>(ESP.getPsramSize()));
    check(M5.Power.getBatteryLevel() >= 0, "battery readable");
}

void showResult() {
    auto& d = M5Cardputer.Display;
    d.fillScreen(TFT_BLACK);
    d.setFont(&fonts::FreeSerifBold9pt7b);
    d.setTextDatum(middle_center);
    d.setTextColor(g_fail ? TFT_RED : TFT_GREEN, TFT_BLACK);
    d.drawString(g_fail ? "SELF-TEST FAILED" : "SELF-TEST PASSED", 120, 50);
    d.setFont(&fonts::Font0);
    d.setTextColor(TFT_WHITE, TFT_BLACK);
    char line[48];
    std::snprintf(line, sizeof(line), "%d passed, %d failed", g_pass, g_fail);
    d.drawString(line, 120, 80);
    d.setTextDatum(top_left);
}

}  // namespace

void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.fillScreen(TFT_BLACK);
    M5Cardputer.Display.setCursor(4, 4);
    M5Cardputer.Display.print("self-test running...");

    Serial.begin(115200);
    delay(800);

    Serial.println();
    Serial.println("######## ORTHRUS ON-DEVICE SELF-TEST ########");

    testPower();
    testEngineParity();
    testRadioBringUp();
    testRadioParamChanges();
    testRadioSweep();
    testSharedBusStress();
    testHeapSoak();
    testGps();
    testI2C();

    Serial.println();
    Serial.printf("######## RESULT: %d passed, %d failed ########\n", g_pass, g_fail);
    showResult();
}

void loop() { delay(1000); }
