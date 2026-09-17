#include "dot11/capture.h"

#include <cstdio>
#include <cstring>

namespace orthrus::dot11 {

Quality Target::quality() const {
    uint8_t pair = 0;
    const bool hs = messagePair(pair);
    if (hs && havePmkid) return Quality::Both;
    if (hs)              return Quality::Handshake;
    if (havePmkid)       return Quality::Pmkid;
    if (eapolFrames > 0) return Quality::Fragment;
    return Quality::Nothing;
}

bool Target::messagePair(uint8_t& out) const {
    // Everything below needs the MIC-bearing message stored verbatim. Without
    // it there is nothing to hash against, however many frames went past.
    if (!haveM2 || eapolLen == 0 || !haveAnonce) return false;

    // M1 + M2 is the cleanest pairing: the AP's nonce from M1, the client's MIC
    // and exact EAPOL bytes from M2, and the same replay counter on both.
    if (haveM1 && anonceFromM1 && rcM1 == rcM2) {
        out = kPairM1M2;
        return true;
    }

    // M2 + M3 works too. M3 is the AP replying to M2, so its counter is the
    // next one up -- that increment is the check, not equality.
    if (haveM3 && rcM3 == rcM2 + 1) {
        out = kPairM2M3;
        return true;
    }

    // We have the pieces but the counters do not agree. This still cracks, and
    // pretending otherwise would throw away real captures on busy networks
    // where a retransmission shifted a counter. It is flagged so the pairing is
    // never mistaken for a protocol-verified one.
    if (haveM1 && anonceFromM1) {
        // cppcheck-suppress badBitmaskCheck  ; kPairM1M2 is 0, and naming it
        // here is what makes the pairing readable next to the M2M3 case below.
        out = kPairM1M2 | kPairNotReplayChecked;
        return true;
    }
    if (haveM3) {
        out = kPairM2M3 | kPairNotReplayChecked;
        return true;
    }

    return false;
}

void Table::clear() {
    for (uint8_t i = 0; i < kMaxTargets; i++) targets_[i] = Target{};
    for (uint8_t i = 0; i < kMaxNames; i++)   names_[i] = Name{};
    count_     = 0;
    nameCount_ = 0;
    nameNext_  = 0;
    dropped_   = 0;
}

int Table::find(const uint8_t bssid[kMacLen], const uint8_t sta[kMacLen]) const {
    for (uint8_t i = 0; i < count_; i++) {
        if (macEqual(targets_[i].bssid, bssid) && macEqual(targets_[i].sta, sta))
            return static_cast<int>(i);
    }
    return -1;
}

const Table::Name* Table::lookupName(const uint8_t bssid[kMacLen]) const {
    for (uint8_t i = 0; i < kMaxNames; i++) {
        if (names_[i].used && macEqual(names_[i].bssid, bssid)) return &names_[i];
    }
    return nullptr;
}

void Table::noteBeacon(const uint8_t bssid[kMacLen], const char* ssid,
                       uint8_t channel, int8_t rssi) {
    if (bssid == nullptr || macIsGroup(bssid)) return;

    // A hidden network has no name to cache, but its channel is still worth
    // knowing, so an empty SSID is stored rather than rejected.
    const char* name = ssid ? ssid : "";

    Name* slot = nullptr;
    for (uint8_t i = 0; i < kMaxNames; i++) {
        if (names_[i].used && macEqual(names_[i].bssid, bssid)) { slot = &names_[i]; break; }
    }

    if (slot == nullptr) {
        // Round robin once full. The cache exists to name handshakes, and the
        // oldest entry is the one least likely to be part of a live one.
        uint8_t i;
        if (nameCount_ < kMaxNames) {
            i = nameCount_++;
        } else {
            i = nameNext_;
            nameNext_ = static_cast<uint8_t>((nameNext_ + 1) % kMaxNames);
        }
        names_[i] = Name{};
        std::memcpy(names_[i].bssid, bssid, kMacLen);
        names_[i].used = true;
        slot = &names_[i];
    }

    // A later beacon with a real name replaces a cached blank: the first frames
    // off a hidden AP carry neither.
    if (name[0] != '\0') std::snprintf(slot->ssid, kSsidBuf, "%s", name);
    if (channel) slot->channel = channel;

    // Push onto any target already holding a handshake from this AP. A capture
    // taken before the beacon arrived is common: the client joins, we hear the
    // handshake, and the next beacon is up to a hundred milliseconds later.
    for (uint8_t i = 0; i < count_; i++) {
        if (!macEqual(targets_[i].bssid, bssid)) continue;
        if (name[0] != '\0' && !targets_[i].named())
            std::snprintf(targets_[i].ssid, kSsidBuf, "%s", name);
        if (channel) {
            targets_[i].channel           = channel;
            targets_[i].channelFromBeacon = true;
        }
        if (rssi != 0) targets_[i].rssi = rssi;
    }
}

Target* Table::ingest(const uint8_t bssid[kMacLen], const uint8_t sta[kMacLen],
                      const KeyFrame& kf, const uint8_t* payload, size_t payloadLen,
                      uint8_t channel, int8_t rssi, uint32_t nowMs) {
    if (bssid == nullptr || sta == nullptr) return nullptr;
    if (kf.message == Message::Unknown) return nullptr;

    // A group address on either end is not a handshake between two parties.
    // Broadcast EAPOL exists, but it is the group key exchange, not the
    // four-way, and it has already been filtered out by the pairwise bit.
    if (macIsGroup(bssid) || macIsGroup(sta)) return nullptr;
    if (macEqual(bssid, sta)) return nullptr;

    int idx = find(bssid, sta);
    if (idx < 0) {
        if (count_ >= kMaxTargets) {
            dropped_++;
            return nullptr;
        }
        idx = count_++;
        targets_[idx] = Target{};
        std::memcpy(targets_[idx].bssid, bssid, kMacLen);
        std::memcpy(targets_[idx].sta, sta, kMacLen);
        targets_[idx].firstSeenMs = nowMs;
        targets_[idx].channel     = channel;

        if (const Name* n = lookupName(bssid)) {
            std::snprintf(targets_[idx].ssid, kSsidBuf, "%s", n->ssid);
            if (n->channel) {
                targets_[idx].channel           = n->channel;
                targets_[idx].channelFromBeacon = true;
            }
        }
    }

    Target& t = targets_[idx];
    t.lastSeenMs = nowMs;
    t.eapolFrames++;
    // Only fill in the channel we received on when no beacon has told us the
    // real one -- see channelFromBeacon.
    if (channel && !t.channelFromBeacon) t.channel = channel;
    if (rssi != 0) t.rssi = rssi;

    switch (kf.message) {
        case Message::M1:
            t.haveM1 = true;
            t.rcM1   = kf.replayCounter;
            if (!kf.nonceIsZero) {
                std::memcpy(t.anonce, kf.nonce, kNonceLen);
                t.haveAnonce   = true;
                t.anonceFromM1 = true;
            }
            {
                uint8_t p[kPmkidLen];
                if (extractPmkid(kf, p)) {
                    std::memcpy(t.pmkid, p, kPmkidLen);
                    t.havePmkid = true;
                }
            }
            break;

        case Message::M2:
            t.haveM2 = true;
            t.rcM2   = kf.replayCounter;
            storeMicFrame(t, kf, payload, payloadLen);
            break;

        case Message::M3:
            t.haveM3 = true;
            t.rcM3   = kf.replayCounter;
            // M3 carries the same ANonce the AP sent in M1. Taking it here is
            // what makes an M2+M3 capture usable when M1 was missed -- which is
            // most of the time, because M1 is the frame that goes past while
            // you are still hopping onto the channel.
            if (!kf.nonceIsZero && !t.anonceFromM1) {
                std::memcpy(t.anonce, kf.nonce, kNonceLen);
                t.haveAnonce   = true;
                t.anonceFromM1 = false;
            }
            break;

        case Message::M4:
            t.haveM4 = true;
            break;

        default:
            break;
    }

    return &t;
}

void Table::storeMicFrame(Target& t, const KeyFrame& kf, const uint8_t* payload,
                          size_t payloadLen) {
    if (payload == nullptr) return;

    // Trust the frame's own declared length over the buffer length. Drivers
    // hand over padding below the 802.1X layer, and hashing the padding as if
    // it were part of the message produces a MIC that never matches.
    size_t n = kf.payloadLen;
    if (n == 0 || n > payloadLen) n = payloadLen;

    if (n > kEapolMax) {
        // Honest rather than silently truncated: a clipped EAPOL blob would
        // export cleanly and then fail to crack with no explanation.
        t.eapolOversize = true;
        return;
    }

    std::memcpy(t.eapol, payload, n);
    t.eapolLen = static_cast<uint16_t>(n);

    // The MIC is computed over the frame with the MIC field zeroed, so that is
    // the form both endpoints hashed and the form a cracker recomputes.
    if (t.eapolLen >= kMicOffset + kMicLen)
        std::memset(t.eapol + kMicOffset, 0, kMicLen);

    std::memcpy(t.mic, kf.mic, kMicLen);
    t.eapolOversize = false;
}

uint8_t Table::exportable() const {
    uint8_t n = 0;
    for (uint8_t i = 0; i < count_; i++) {
        if (targets_[i].quality() >= Quality::Pmkid) n++;
    }
    return n;
}

const char* qualityName(Quality q) {
    switch (q) {
        case Quality::Nothing:   return "--";
        case Quality::Fragment:  return "PART";
        case Quality::Pmkid:     return "PMKID";
        case Quality::Handshake: return "4WAY";
        case Quality::Both:      return "FULL";
    }
    return "--";
}

const char* qualityDetail(Quality q) {
    switch (q) {
        case Quality::Nothing:
            return "Nothing captured. Absence of a handshake means nobody joined "
                   "while you were on this channel, not that the network is safe.";
        case Quality::Fragment:
            return "Some handshake frames, but not a set that pairs up. Stay on "
                   "this channel: the next client to join completes it.";
        case Quality::Pmkid:
            return "PMKID captured. Offline-attackable on its own, with no client "
                   "involved. It does not reveal whether the passphrase is weak.";
        case Quality::Handshake:
            return "Usable message pair. The passphrase is now subject to offline "
                   "guessing at the attacker's own pace. Export and crack "
                   "elsewhere.";
        case Quality::Both:
            return "PMKID and a usable message pair. Two independent routes to the "
                   "same offline attack; the strongest evidence this surface "
                   "produces.";
    }
    return "";
}

}  // namespace orthrus::dot11
