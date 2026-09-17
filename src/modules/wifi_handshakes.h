// Harvest: WPA/WPA2 handshake and PMKID capture.
//
// This is the surface that turns "the network uses WPA2" into a finding a
// client can act on. A captured handshake means the passphrase is subject to
// offline guessing -- an attacker tests candidates on their own hardware, at
// their own pace, with nothing on the network able to see it or slow it down.
//
// PASSIVE. DELIBERATELY.
//
// The usual way to force a handshake is to knock a client off the network and
// watch it come back. This device does not do that, and it is not an oversight:
// a deauthentication flood is a denial of service against equipment that may
// not be in scope, against people who did not agree to lose their connection,
// and it is the single feature most likely to get a tool like this pulled from
// sale. Orthrus listens. Clients join networks constantly, and PMKID capture
// needs no client at all.
//
// What that costs is honest and worth stating: you may sit on a channel and
// hear nothing. That is a quiet channel, not a secure network, and the screen
// says exactly that rather than showing an encouraging zero.
//
// WHAT IT PRODUCES
//
//   /orthrus/harvest-NNN.22000   hashcat mode 22000, ready to crack elsewhere
//   /orthrus/harvest-NNN.pcap    the frames themselves, for Wireshark/hcxtools
//
// Cracking happens on a laptop with a GPU. This device captures and says what
// it has; it never claims to have recovered a passphrase.

#pragma once

#include <FS.h>

#include <cstdint>

#include "dot11/capture.h"

namespace orthrus::modules {

class WifiHandshakes {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Detail, Saved };

    void pump();
    void drain();
    void hop();

    // origLen is the length the frame had ON THE AIR, which differs from len
    // whenever the frame was clipped into a ring slot. The pcap record needs
    // both or it silently claims the clipped length was the real one.
    void handleBeacon(const uint8_t* frame, uint16_t len, const dot11::FrameInfo& fi,
                      uint8_t channel, int8_t rssi, uint16_t origLen);
    void handleData(const uint8_t* frame, uint16_t len, const dot11::FrameInfo& fi,
                    uint8_t channel, int8_t rssi, uint16_t origLen);

    bool openPcap();
    void writePcapFrame(const uint8_t* frame, uint16_t len, uint16_t origLen);
    bool saveHashes();

    // Whether this access point's beacon has already gone into the capture
    // file. hcxtools and Wireshark both want the beacon to put a name to a
    // handshake, and one per network is enough -- writing every beacon would
    // bury the frames that matter under ten a second per access point.
    bool beaconAlreadyWritten(const uint8_t bssid[dot11::kMacLen]);

    void drawList();
    void drawDetail();
    void drawSaved();
    bool handleKeys();

    // ~7 KB. Static storage via the single module instance in main; never a
    // local. See the warning in dot11/capture.h.
    dot11::Table table_;

    int  selected_ = 0;
    int  scroll_   = 0;
    View view_     = View::List;

    uint8_t  channel_     = 1;
    bool     locked_      = false;
    uint32_t lastHopMs_   = 0;
    uint32_t lastDrawMs_  = 0;

    uint32_t framesSeen_  = 0;
    uint32_t eapolSeen_   = 0;
    uint32_t beaconsSeen_ = 0;

    static constexpr uint8_t kMaxNamedBeacons = 16;
    uint8_t beaconWritten_[kMaxNamedBeacons][dot11::kMacLen] = {{0}};
    uint8_t beaconWrittenCount_ = 0;

    File pcap_;
    bool pcapOpen_    = false;
    bool pcapFailed_  = false;
    char pcapPath_[40]  = {0};
    char hashPath_[40]  = {0};
    uint32_t pcapFrames_ = 0;

    // Result of the last save, for the confirmation screen.
    uint16_t savedLines_ = 0;
    bool     saveOk_     = false;
};

}  // namespace orthrus::modules
