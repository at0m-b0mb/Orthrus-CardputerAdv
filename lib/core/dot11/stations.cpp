#include "dot11/stations.h"

#include <cstdio>
#include <cstring>

namespace orthrus::dot11 {

bool macIsRandomised(const uint8_t mac[kMacLen]) {
    // Bit 1 of the first octet is the locally-administered bit. Bit 0 is the
    // group bit and is a different thing entirely; confusing the two reports
    // every broadcast address as a randomised phone.
    return (mac[0] & 0x02) != 0;
}

void StationTable::clear() {
    for (uint8_t i = 0; i < kMaxStations; i++) stations_[i] = Station{};
    count_   = 0;
    dropped_ = 0;
}

int StationTable::find(const uint8_t mac[kMacLen]) const {
    for (uint8_t i = 0; i < count_; i++)
        if (macEqual(stations_[i].mac, mac)) return static_cast<int>(i);
    return -1;
}

int StationTable::evictOldest() {
    int oldest = 0;
    for (uint8_t i = 1; i < count_; i++)
        if (stations_[i].lastSeenMs < stations_[oldest].lastSeenMs) oldest = i;
    return oldest;
}

Station* StationTable::touch(const uint8_t mac[kMacLen], int8_t rssi,
                             uint32_t nowMs) {
    if (mac == nullptr) return nullptr;

    // An access point's own frames and broadcast destinations are not devices
    // in the room. Only individually-addressed sources are.
    if (macIsGroup(mac)) return nullptr;

    int idx = find(mac);
    if (idx < 0) {
        if (count_ >= kMaxStations) {
            idx = evictOldest();
            dropped_++;
            stations_[idx] = Station{};
        } else {
            idx = count_++;
            stations_[idx] = Station{};
        }
        std::memcpy(stations_[idx].mac, mac, kMacLen);
        stations_[idx].randomised  = macIsRandomised(mac);
        stations_[idx].firstSeenMs = nowMs;
    }

    Station& s = stations_[idx];
    s.frames++;
    s.lastSeenMs = nowMs;
    if (rssi != 0) {
        s.rssi = rssi;
        if (rssi > s.bestRssi) s.bestRssi = rssi;
    }
    return &s;
}

void StationTable::noteProbe(const uint8_t mac[kMacLen], const char* ssid,
                             int8_t rssi, uint32_t nowMs) {
    Station* s = touch(mac, rssi, nowMs);
    if (s == nullptr) return;
    s->probes++;

    // A broadcast probe names nothing. It is counted -- a device probing at all
    // is worth seeing -- but there is no network to record, and storing an
    // empty string would put a blank row in front of the operator.
    if (ssid == nullptr || ssid[0] == '\0') return;

    for (uint8_t i = 0; i < s->ssidCount; i++)
        if (std::strcmp(s->ssids[i], ssid) == 0) return;   // already known

    if (s->ssidCount >= kMaxProbesPerStation) return;
    std::snprintf(s->ssids[s->ssidCount], kSsidBuf, "%s", ssid);
    s->ssidCount++;
}

void StationTable::noteAssociation(const uint8_t mac[kMacLen],
                                   const uint8_t bssid[kMacLen], int8_t rssi,
                                   uint32_t nowMs) {
    Station* s = touch(mac, rssi, nowMs);
    if (s == nullptr || bssid == nullptr) return;
    if (macIsGroup(bssid)) return;

    std::memcpy(s->bssid, bssid, kMacLen);
    s->associated = true;
}

uint8_t StationTable::talkers() const {
    uint8_t n = 0;
    for (uint8_t i = 0; i < count_; i++)
        if (stations_[i].hasNamedProbes()) n++;
    return n;
}

}  // namespace orthrus::dot11
