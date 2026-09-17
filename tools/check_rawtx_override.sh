#!/usr/bin/env bash
#
# Proves that OUR definition of ieee80211_raw_frame_sanity_check is the one that
# linked, in every build that can transmit.
#
# This exists because the first attempt did not work and nothing said so. The
# link used -Wl,--wrap, which cannot rewrite a call that libnet80211 makes to
# itself inside one object file -- and GNU ld emits no diagnostic when a --wrap
# matches nothing. The build was green, cppcheck was clean, the tests passed,
# and every single deauthentication frame was rejected by the IDF with
# "unsupport frame type". The Deauth surface counted up to zero frames sent and
# reported "no effect seen", which reads exactly like a network that is properly
# protected.
#
# A runtime probe in wifi_deauth.cpp catches this on the device. This catches it
# in CI, before anyone flashes it.
set -euo pipefail

SYMBOL="ieee80211_raw_frame_sanity_check"
OURS="wifi_deauth.cpp.o"
status=0

for env in cardputer-adv cardputer-adv-hid; do
    map=".pio/build/${env}/firmware.map"
    if [[ ! -f "$map" ]]; then
        echo "skip ${env}: not built"
        continue
    fi

    # The linker lists the section, then on the next line the address and the
    # object file that supplied it. Ours must be the one that got an address.
    supplier=$(grep -A1 "^ \.text\.${SYMBOL}\$" "$map" \
               | grep -E "^ +0x[0-9a-f]+ +[0-9a-fx]+ .*\.o" \
               | grep -v " 0x0000000000000000 " \
               | head -1 || true)

    if [[ -z "$supplier" ]]; then
        # Fall back to a looser match: any placed copy of the symbol.
        supplier=$(grep -A1 "\.text\.${SYMBOL}" "$map" | grep "\.o" | head -1 || true)
    fi

    if [[ "$supplier" == *"$OURS"* ]]; then
        echo "ok   ${env}: ${SYMBOL} supplied by ${OURS}"
    else
        echo "FAIL ${env}: ${SYMBOL} did NOT come from ${OURS}"
        echo "     got: ${supplier:-<nothing placed>}"
        echo "     raw 802.11 transmit will be rejected; Deauth will send nothing."
        status=1
    fi
done

exit $status
