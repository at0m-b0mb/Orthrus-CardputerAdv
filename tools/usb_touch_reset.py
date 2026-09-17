"""Pre-upload hook for the HID build.

With ARDUINO_USB_MODE=0 the device presents a TinyUSB CDC, and esptool's DTR/RTS
sequence cannot push it into download mode -- a plain upload fails with "No
serial data received". The Arduino USB stack does implement the standard touch
reset though: open the port at 1200 baud with DTR low and it reboots into the
ROM bootloader.

Verified on hardware: without this, flashing the HID build needs the BOOT
button. With it, it does not.

THE PART THAT IS EASY TO GET WRONG

The bootloader does not come back on the same port. It is a different USB
device with different descriptors, so the operating system gives it a different
name -- and esptool, which was told the old name either by the command line or
by PlatformIO's own detection, then fails with "port is busy or doesn't exist"
on a board that is sitting there waiting for it.

So this hook does not just touch and hope. It records which ports existed
before, touches, waits for the set to change, and points the upload at whatever
appeared. Measured the hard way: the first version pinned the old port name and
failed every time the name changed.
"""

import glob
import time

Import("env")  # noqa: F821  (injected by PlatformIO)

# macOS calls them cu.usbmodem*, Linux ttyACM*. Windows has no stable glob, and
# there the hook steps aside rather than guessing.
PATTERNS = ("/dev/cu.usbmodem*", "/dev/ttyACM*")

SETTLE_SECONDS = 4.0
POLL_SECONDS = 0.2


def ports():
    found = []
    for pattern in PATTERNS:
        found.extend(glob.glob(pattern))
    return set(found)


def touch_reset(source, target, env):
    try:
        import serial
    except ImportError:
        print("[usb_touch_reset] pyserial unavailable, skipping")
        return

    before = ports()
    if not before:
        print("[usb_touch_reset] no serial device found, leaving it to esptool")
        return

    # Touch whatever the upload is aimed at. Falling back to the only port
    # present is right for the common case of one board on the desk; with
    # several, PlatformIO has already been told which one.
    wanted = env.subst("$UPLOAD_PORT")
    port = wanted if wanted in before else sorted(before)[0]

    print("[usb_touch_reset] touching %s at 1200 baud" % port)
    try:
        s = serial.Serial(port, 1200)
        s.dtr = False
        time.sleep(0.3)
        s.close()
    except Exception as exc:  # noqa: BLE001
        # Already in download mode, or somebody has the port open. Either way
        # esptool gets its turn; failing here would stop an upload that might
        # have worked.
        print("[usb_touch_reset] touch failed (%s), continuing" % exc)
        return

    # Wait for the ROM bootloader to enumerate, and take the name it arrives
    # under. A fixed sleep plus a hard-coded port name is what the first version
    # did, and it broke the moment the name changed.
    deadline = time.time() + SETTLE_SECONDS
    while time.time() < deadline:
        time.sleep(POLL_SECONDS)
        now = ports()
        appeared = now - before
        if appeared:
            new_port = sorted(appeared)[0]
            print("[usb_touch_reset] bootloader on %s" % new_port)
            env.Replace(UPLOAD_PORT=new_port)
            # Give the device a moment past enumeration before esptool opens it.
            time.sleep(0.5)
            return
        if port not in now and now:
            # The port was renamed in place rather than added alongside.
            new_port = sorted(now)[0]
            print("[usb_touch_reset] bootloader on %s" % new_port)
            env.Replace(UPLOAD_PORT=new_port)
            time.sleep(0.5)
            return

    print("[usb_touch_reset] no new port appeared; "
          "the board may already be in download mode")


env.AddPreAction("upload", touch_reset)  # noqa: F821
