#!/usr/bin/env python3
# Linux userspace tool for A4Tech Bloody A60 (09da:72e7), reverse engineered.
# Talks to the mouse config interface (usage page 0xFF32) via hidraw feature report 7.
import os, sys, glob, time, fcntl, struct

VIDPID = '000009DA:000072E7'          # kernel pads HID_ID to 8 hex digits per field

def _ioc(d, nr, size): return (d << 30) | (size << 16) | (ord('H') << 8) | nr
_SF = lambda n: _ioc(3, 6, n)         # HIDIOCSFEATURE
_GF = lambda n: _ioc(3, 7, n)         # HIDIOCGFEATURE

def find_dev():
    for h in glob.glob('/sys/class/hidraw/hidraw*'):
        ue = open(h + '/device/uevent').read()
        if VIDPID in ue and 'input2' in ue: return '/dev/' + os.path.basename(h)
    return None

def open_dev():
    p = find_dev()
    if not p: sys.exit('Bloody A60 config interface not found (is the mouse plugged in?)')
    try: return os.open(p, os.O_RDWR)
    except PermissionError: sys.exit(f'No access to {p}. Install the udev rule or run with sudo.')

def xfer(fd, op, data=b'', write=False):
    # Request: [07][op][00][00][80=write/00=read][00][00][00][data...], 64 bytes.
    buf = bytearray(64)
    buf[0], buf[1], buf[4] = 7, op, (0x80 if write else 0x00)
    buf[8:8+len(data)] = data
    fcntl.ioctl(fd, _SF(64), bytes(buf))
    out = bytearray(64); out[0] = 7
    fcntl.ioctl(fd, _GF(64), out)
    return bytes(out)

def info(fd):
    a = xfer(fd, 0x1f); b = xfer(fd, 0x02)
    fw_ver = a[12]
    usage  = a[10] | (a[11] << 8)         # 0x04EE
    fw_code = b[20] | (b[21] << 8)        # 0x04EC
    bl = xfer(fd, 0x11)[8]
    print(f'Model        A60cir (sensor P3332A)')
    print(f'Firmware     code 0x{fw_code:04X}, version 0x{fw_ver:02X}')
    print(f'Config usage 0x{usage:04X}')
    print(f'Backlight    level {bl} (0-3)')
    bm = b[24:55]
    slots = [(bm[i], bm[i+1]) for i in range(0, len(bm)-1, 2)]
    assigned = sum(1 for _, act in slots if act != 0xff)
    print(f'Buttons      {len(slots)} slots, {assigned} assigned')

def backlight(fd, level=None):
    if level is None:
        print(xfer(fd, 0x11)[8]); return
    level = int(level)
    if not 0 <= level <= 3: sys.exit('level must be 0-3')
    xfer(fd, 0x11, bytes([level]), write=True)
    print('backlight ->', xfer(fd, 0x11)[8])

def dump(fd):
    # Read-only sweep of safe opcodes (skips the ranges that reboot the mouse).
    REBOOT = {0x00, 0x86} | set(range(0xa7, 0xc2)) | set(range(0xd6, 0x100))
    for op in range(0x100):
        if op in REBOOT: continue
        r = xfer(fd, op)
        if any(r[2:]):
            last = max(i for i in range(64) if r[i])
            print(f'{op:02x}: {r[2:last+1].hex(" ")}')
        time.sleep(0.02)

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'info'
    fd = open_dev()
    if   cmd == 'info':      info(fd)
    elif cmd == 'backlight': backlight(fd, sys.argv[2] if len(sys.argv) > 2 else None)
    elif cmd == 'dump':      dump(fd)
    elif cmd == 'raw':       print(xfer(fd, int(sys.argv[2], 16)).hex(' '))
    else: sys.exit('usage: bloody.py [info|backlight [0-3]|dump|raw <op>]')

if __name__ == '__main__':
    main()
