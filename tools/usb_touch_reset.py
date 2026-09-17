"""Pre-upload hook for the HID build.

With ARDUINO_USB_MODE=0 the device presents a TinyUSB CDC, and esptool's DTR/RTS
sequence cannot push it into download mode -- a plain upload fails with "No
serial data received". The Arduino USB stack does implement the standard touch
reset though: open the port at 1200 baud with DTR low and it reboots into the
ROM bootloader, which re-enumerates as the USB-JTAG port esptool expects.

Verified on hardware: without this, flashing the HID build needs the BOOT
button. With it, it does not.
"""

import glob
import time

Import("env")  # noqa: F821  (injected by PlatformIO)


def touch_reset(source, target, env):
    try:
        import serial
    except ImportError:
        print("[usb_touch_reset] pyserial unavailable, skipping")
        return

    # The TinyUSB port carries a serial number; the ROM's JTAG port does not.
    candidates = [p for p in glob.glob("/dev/cu.usbmodem*")
                  if not p.endswith("2101")]
    if not candidates:
        print("[usb_touch_reset] already in download mode")
        return

    port = candidates[0]
    print("[usb_touch_reset] touching %s at 1200 baud" % port)
    try:
        s = serial.Serial(port, 1200)
        s.dtr = False
        time.sleep(0.3)
        s.close()
    except Exception as exc:                      # noqa: BLE001
        print("[usb_touch_reset] touch failed: %s" % exc)
        return

    # Give the ROM a moment to enumerate before esptool goes looking.
    time.sleep(2.5)
    print("[usb_touch_reset] done")


env.AddPreAction("upload", touch_reset)  # noqa: F821
