#include "hal/rawtx.h"

#include <WiFi.h>
#include <esp_wifi.h>

#include "attack/family.h"

// Distinctive enough that no real frame-sanity call would ever use it.
static constexpr int32_t kRawTxProbe = 0x07A1B2C3;

// THE OVERRIDE. One definition for the whole firmware -- see rawtx.h for why
// this file exists and why --wrap was tried first and does not work here.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2,
                                                int32_t arg3) {
    (void)arg2;
    (void)arg3;
    if (arg == kRawTxProbe) return 1;   // the probe: this override is linked
    return 0;                           // every real frame: permitted
}

namespace orthrus::hal {

bool rawTxAvailable() {
    // Calling the plain name reaches whichever definition won, so a
    // distinctive answer is proof that it was ours.
    return ieee80211_raw_frame_sanity_check(kRawTxProbe, 0, 0) == 1;
}

bool rawTxBegin(uint8_t channel) {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, true);

    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_ps(WIFI_PS_NONE);

    if (!rawTxSetChannel(channel)) return false;
    return true;
}

bool rawTxSetChannel(uint8_t channel) {
    if (channel == 0) return false;
    // The regulatory clamp is consulted HERE, at the one place a channel is
    // actually tuned, rather than only in the plan. A surface that recomputed
    // its own channel mid-run would otherwise bypass the gate entirely.
    if (!attack::regionAllows(channel)) return false;
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) == ESP_OK;
}

bool rawTxSend(const uint8_t* frame, size_t len) {
    if (frame == nullptr || len == 0) return false;
    // en_sys_seq=false: the MAC does NOT fill the sequence control field in,
    // which is why dot11::Sequencer exists and every builder advances it.
    return esp_wifi_80211_tx(WIFI_IF_STA, frame, static_cast<int>(len), false) ==
           ESP_OK;
}

void rawTxEnd() {
    esp_wifi_set_promiscuous(false);
}

}  // namespace orthrus::hal
