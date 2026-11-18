// Raw 802.11 transmission, and the one override that makes it possible.
//
// WHY THIS IS A SHARED HAL FILE AND NOT A COPY PER MODULE
//
// The ESP-IDF refuses to transmit a forged management frame through
// esp_wifi_80211_tx: ieee80211_raw_frame_sanity_check rejects it. Overriding
// that check means defining a symbol the IDF already defines, which can only
// happen ONCE in a link. The 802.11w test used to carry the definition inside
// its own translation unit, which was fine while it was the only surface that
// transmitted. It is not any more, and a second copy would not have produced a
// subtle bug -- it would have failed the link outright.
//
// THE LINKER TRICK, AND WHY IT IS THE SECOND ONE TRIED
//
// This was -Wl,--wrap first, on the sound reasoning that it redirects exactly
// one call rather than reaching for --allow-multiple-definition and disabling
// duplicate-symbol detection across the whole link. The reasoning was good and
// the result did not work: libnet80211 both DEFINES and CALLS this function
// inside one object file, so the call is an intra-object relocation no linker
// can rewrite -- and ld says nothing at all when a --wrap matches nothing. The
// build stayed green while every single transmit failed with "unsupport frame
// type", the screen counting up to zero frames sent and concluding "no effect
// seen", which reads exactly like a properly protected network. Proved with nm
// on the linked ELF, where __wrap_ was absent entirely.
//
// So it is a plain strong redefinition plus --allow-multiple-definition in
// platformio.ini, which is what Basanos arrived at after hitting the same wall
// on real hardware. The ODR concern is answered by the runtime probe below
// rather than by the linker.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::hal {

// True when OUR definition of the sanity check is the one that linked.
//
// A link-time trick that silently stops working is exactly how a transmitting
// surface came to report healthy while sending nothing, so the firmware asks
// the question instead of assuming. One magic argument returns a distinctive
// answer no real frame-sanity call would ever ask for; if the library's
// definition linked instead it answers 0 like any other, and the surface says
// "injection unavailable in this build" rather than arming.
bool rawTxAvailable();

// Brings the radio up for transmission and reception on one channel.
//
// Does the two things that are easy to forget and silent when forgotten:
//   WIFI_PS_NONE     -- Arduino's STA_START handler enables WIFI_PS_MIN_MODEM,
//                       and a radio that periodically sleeps misses frames and
//                       misses them silently.
//   WIFI_STORAGE_RAM -- otherwise every mode change is written to flash.
//
// Returns false when the radio refused to start.
bool rawTxBegin(uint8_t channel);

// Parks the radio on a channel. Refused, rather than silently retuned, when
// the attack layer's regulatory clamp does not permit it.
bool rawTxSetChannel(uint8_t channel);

// Sends one frame. Returns true when the driver accepted it.
//
// Accepted is not received: nothing on this side can tell whether anybody
// heard it, which is why every surface that uses this also listens afterwards
// and reports what it actually observed rather than what it sent.
bool rawTxSend(const uint8_t* frame, size_t len);

// Puts the radio back the way an idle firmware expects it.
void rawTxEnd();

}  // namespace orthrus::hal
