// Emits, as JSON, exactly what the device screens would show for a scripted
// site survey.
//
// The point is that nothing here is hand-authored screen text. Real PHYPayload
// bytes go through the real parser, into the real census, and out through the
// real grader -- the same four files the firmware links. If a grade in the
// README is wrong, the engine is wrong, and a test will say so.
//
// Build:
//   g++ -std=c++17 -I lib/core tools/screendump/main.cpp lib/core/lorawan/*.cpp \
//       -o build/screendump

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "lorawan/census.h"
#include "lorawan/findings.h"
#include "lorawan/phy.h"
#include "lorawan/region.h"

using namespace orthrus::lorawan;

namespace {

void pushU16LE(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t(x >> 8));
}
void pushU32LE(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t((x >> 8) & 0xFF));
    v.push_back(uint8_t((x >> 16) & 0xFF));
    v.push_back(uint8_t((x >> 24) & 0xFF));
}

std::vector<uint8_t> uplink(uint32_t devAddr, uint16_t fCnt, bool adr, uint8_t fPort,
                            const std::vector<uint8_t>& frm) {
    std::vector<uint8_t> f;
    f.push_back(0x40);
    pushU32LE(f, devAddr);
    f.push_back(adr ? 0x80 : 0x00);
    pushU16LE(f, fCnt);
    f.push_back(fPort);
    f.insert(f.end(), frm.begin(), frm.end());
    pushU32LE(f, 0x11223344);
    return f;
}

std::vector<uint8_t> joinRequest(const uint8_t devEuiBE[8], uint16_t nonce) {
    std::vector<uint8_t> f;
    f.push_back(0x00);
    for (int i = 0; i < 8; i++) f.push_back(0x70);            // JoinEUI, LE
    for (int i = 0; i < 8; i++) f.push_back(devEuiBE[7 - i]);  // DevEUI, LE
    pushU16LE(f, nonce);
    pushU32LE(f, 0xDEADBEEF);
    return f;
}

std::vector<uint8_t> bytesOf(const char* s) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + std::strlen(s));
}

// Plausible AES output: high entropy, not printable.
std::vector<uint8_t> cipher(uint8_t n, uint8_t seed) {
    std::vector<uint8_t> v;
    uint32_t x = 0x9E3779B9u ^ (seed * 2654435761u);
    for (uint8_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        v.push_back(uint8_t(x & 0xFF));
    }
    return v;
}

RxMeta meta(uint32_t t, uint8_t sf, int16_t rssi, uint32_t hz) {
    RxMeta m;
    m.freqHz = hz; m.sf = sf; m.bwKhz = 125;
    m.rssiDbm = rssi; m.snrDb = 8; m.timeMs = t;
    return m;
}

struct Stats { uint32_t crcErrors = 0; uint32_t otherRf = 0; };

void feed(Census& c, const std::vector<uint8_t>& phy, const RxMeta& m) {
    Frame f;
    if (parse(phy.data(), phy.size(), f)) c.observe(f, m);
}

std::string esc(const char* s) {
    std::string out;
    for (const char* p = s; *p; p++) {
        if (*p == '"' || *p == '\\') out += '\\';
        out += *p;
    }
    return out;
}

const char* kindTag(const DeviceRecord& d) {
    return d.kind == DeviceKind::Session ? "session" : "joiner";
}

std::string labelOf(const DeviceRecord& d) {
    char buf[24];
    if (d.kind == DeviceKind::Session)
        std::snprintf(buf, sizeof(buf), "%08X", d.devAddr);
    else
        std::snprintf(buf, sizeof(buf), "%02X%02X%02X%02X*", d.devEui[4], d.devEui[5],
                      d.devEui[6], d.devEui[7]);
    return buf;
}

}  // namespace

int main() {
    Census census;
    Stats stats;
    uint32_t t = 0;

    const uint32_t ch0 = 868100000, ch1 = 868300000, ch2 = 867500000;

    // 1. Weather sensor shipping cleartext JSON. The finding that needs no keys.
    for (uint16_t i = 0; i < 14; i++)
        feed(census, uplink(0x26011BDA, uint16_t(100 + i), true, 2,
                            bytesOf("{\"t\":21.5,\"h\":48}")),
             meta(t += 4000, 7, -78, ch0));

    // 2. ABP water meter that rebooted: counter falls from 1204 to 3.
    for (uint16_t i = 0; i < 6; i++)
        feed(census, uplink(0x260ABCDE, uint16_t(1198 + i), false, 1, cipher(12, 3)),
             meta(t += 5000, 9, -101, ch1));
    for (uint16_t i = 0; i < 5; i++)
        feed(census, uplink(0x260ABCDE, uint16_t(3 + i), false, 1, cipher(12, 4)),
             meta(t += 5000, 9, -103, ch1));

    // 3. A device doing everything right.
    for (uint16_t i = 0; i < 52; i++)
        feed(census, uplink(0x26FF0102, uint16_t(500 + i), true, 5, cipher(16, uint8_t(i))),
             meta(t += 2000, 7, -66, ch0));

    // 4. Joiner reusing its DevNonce: a replayable join.
    const uint8_t eui[8] = {0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x04, 0x11, 0x9C};
    const uint16_t nonces[] = {0x4A21, 0x7C03, 0x4A21, 0x91BE, 0x4A21};
    for (uint16_t n : nonces) feed(census, joinRequest(eui, n), meta(t += 30000, 10, -95, ch2));

    // 5. ADR off and stuck at SF12: loud, slow, expensive.
    for (uint16_t i = 0; i < 21; i++)
        feed(census, uplink(0x2600DEAD, uint16_t(7000 + i), false, 1, cipher(8, uint8_t(i))),
             meta(t += 9000, 12, -117, ch2));

    // 6. Two frames only: real, but far too thin to grade highly.
    for (uint16_t i = 0; i < 2; i++)
        feed(census, uplink(0x26001234, uint16_t(9 + i), true, 3, cipher(10, 9)),
             meta(t += 60000, 8, -88, ch1));

    stats.crcErrors = 37;
    stats.otherRf   = 4;

    // Coverage as the device would compute it after sweeping all 8 EU868
    // channels at a single spreading factor.
    const ChannelPlan& p = plan(Region::EU868);
    CaptureContext ctx;
    ctx.listenedMs       = t;
    ctx.channelsCovered  = 8;
    ctx.channelsInRegion = p.uplinkCount;
    ctx.sfCovered        = 2;  // operator stepped two spreading factors
    ctx.sfInRegion       = p.sfCount();

    std::printf("{\n");
    std::printf("  \"live\": {\n");
    std::printf("    \"region\": \"%s\", \"freqMHz\": 868.100, \"sf\": 7,\n", p.name);
    std::printf("    \"devices\": %u, \"frames\": %u, \"crcErrors\": %u, \"otherRf\": %u,\n",
                unsigned(census.size()), unsigned(census.framesObserved()),
                unsigned(stats.crcErrors), unsigned(stats.otherRf));
    std::printf("    \"coveragePercent\": %u, \"channels\": %u, \"sfs\": %u,\n",
                unsigned(ctx.coveragePercent()), unsigned(8), unsigned(p.sfCount()));
    std::printf("    \"litChannel\": 2, \"litSf\": 0,\n");
    std::printf("    \"lastLine\": \"26011BDA c113 -78dBm\", \"hopping\": true\n");
    std::printf("  },\n");

    std::printf("  \"census\": [\n");
    for (size_t i = 0; i < census.size(); i++) {
        const DeviceRecord& d = census.at(i);
        const auto a = assess(d, ctx);
        std::printf("    {\"label\": \"%s\", \"kind\": \"%s\", \"rssi\": %d, "
                    "\"frames\": %u, \"grade\": \"%s\", \"score\": %u, "
                    "\"provisional\": %s}%s\n",
                    labelOf(d).c_str(), kindTag(d), int(d.bestRssiDbm),
                    unsigned(d.framesSeen), gradeName(a.grade), unsigned(a.score),
                    a.provisional ? "true" : "false",
                    (i + 1 < census.size()) ? "," : "");
    }
    std::printf("  ],\n");

    // Dossier for the worst device, chosen by score rather than by hand.
    size_t worst = 0;
    uint8_t worstScore = 255;
    for (size_t i = 0; i < census.size(); i++) {
        const auto a = assess(census.at(i), ctx);
        if (a.score < worstScore) { worstScore = a.score; worst = i; }
    }
    const DeviceRecord& wd = census.at(worst);
    const auto wa = assess(wd, ctx);

    std::printf("  \"dossier\": {\n");
    std::printf("    \"label\": \"%s\", \"grade\": \"%s\", \"score\": %u, \"frames\": %u,\n",
                labelOf(wd).c_str(), gradeName(wa.grade), unsigned(wa.score),
                unsigned(wd.framesSeen));
    std::printf("    \"provisional\": %s,\n", wa.provisional ? "true" : "false");
    std::printf("    \"findings\": [\n");
    for (uint8_t i = 0; i < wa.findings.count; i++) {
        const Finding& f = wa.findings.items[i];
        std::printf("      {\"title\": \"%s\", \"severity\": \"%s\", \"confidence\": %u, "
                    "\"detail\": \"%s\"}%s\n",
                    esc(findingTitle(f.id)).c_str(), severityName(f.sev),
                    unsigned(f.confidence), esc(findingDetail(f.id)).c_str(),
                    (i + 1 < wa.findings.count) ? "," : "");
    }
    std::printf("    ]\n  }\n}\n");
    return 0;
}
