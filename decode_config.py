#!/usr/bin/env python3
# Decrypt Bloody7 config/data files and .sn8encode5 firmware (AES-128-ECB + 32-bit seed XOR), see CONFIG_CIPHER.md
import argparse, os, struct, sys, zlib

KEY_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bloody7.key')  # hex key, written on first run

UNIVERSAL_DELTA = ('a70c88de', 'c82ffd02', 'd98661fb')  # lane deltas of AES_K(0^16), seen in every .sn8encode5


def gen_sbox():
    sbox, p, q = [0] * 256, 1, 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        r = lambda n: ((q << n) | (q >> (8 - n))) & 0xFF
        sbox[p] = q ^ r(1) ^ r(2) ^ r(3) ^ r(4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = gen_sbox()
INV = [0] * 256
for i, v in enumerate(SBOX):
    INV[v] = i


def xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = xt(a), b >> 1
    return r


def expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rc = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rc
            rc = xt(rc)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def enc_block(rk, b):
    s = [x ^ k for x, k in zip(b, rk[0])]
    for r in range(1, 11):
        s = [SBOX[s[(i + 4 * (i % 4)) % 16]] for i in range(16)]
        if r < 10:
            s = sum(([mul(c[0], 2) ^ mul(c[1], 3) ^ c[2] ^ c[3], c[0] ^ mul(c[1], 2) ^ mul(c[2], 3) ^ c[3],
                      c[0] ^ c[1] ^ mul(c[2], 2) ^ mul(c[3], 3), mul(c[0], 3) ^ c[1] ^ c[2] ^ mul(c[3], 2)]
                     for c in (s[j:j + 4] for j in range(0, 16, 4))), [])
        s = [x ^ k for x, k in zip(s, rk[r])]
    return bytes(s)


def dec_block(rk, b):
    s = [x ^ k for x, k in zip(b, rk[10])]
    for r in range(9, -1, -1):
        s = [INV[s[(i - 4 * (i % 4)) % 16]] ^ k for i, k in zip(range(16), rk[r])]
        if r:
            s = sum(([mul(c[0], 14) ^ mul(c[1], 11) ^ mul(c[2], 13) ^ mul(c[3], 9),
                      mul(c[0], 9) ^ mul(c[1], 14) ^ mul(c[2], 11) ^ mul(c[3], 13),
                      mul(c[0], 13) ^ mul(c[1], 9) ^ mul(c[2], 14) ^ mul(c[3], 11),
                      mul(c[0], 11) ^ mul(c[1], 13) ^ mul(c[2], 9) ^ mul(c[3], 14)]
                     for c in (s[j:j + 4] for j in range(0, 16, 4))), [])
    return bytes(s)


def key_ok(key):
    z = enc_block(expand(key), bytes(16))
    return tuple(bytes(x ^ y for x, y in zip(z[i:i + 4], z[:4])).hex() for i in (4, 8, 12)) == UNIVERSAL_DELTA


def load_key(exe_path):
    # cached key first, else pull it from Bloody7.exe: 16 dwords (one byte each) right before the dword S-box
    if os.path.exists(KEY_CACHE):
        key = bytes.fromhex(open(KEY_CACHE).read().strip())
        if key_ok(key):
            return expand(key)
    exe = open(exe_path, 'rb').read()
    i = exe.find(b''.join(bytes([x, 0, 0, 0]) for x in SBOX[:8]))
    if i < 64:
        raise SystemExit(f'{exe_path}: AES tables not found, is this Bloody7.exe?')
    key = exe[i - 64:i:4]
    if not key_ok(key):
        raise SystemExit(f'{exe_path}: key candidate failed the firmware check value')
    open(KEY_CACHE, 'w').write(key.hex() + '\n')
    return expand(key)


def xor_seed(data, seed):
    return bytes(b ^ seed[i % 4] for i, b in enumerate(data))


def decrypt_config(rk, raw):
    if len(raw) < 16 or len(raw) % 16:
        raise ValueError('size not a multiple of 16')
    n = len(raw) - 16
    _, seed, ver, crc = struct.unpack('<4I', raw[n:])
    if zlib.crc32(raw[:n + 12]) != crc:
        raise ValueError('CRC mismatch')
    if not 0x01010101 <= ver <= 0x01010104:
        raise ValueError(f'bad version {ver:#x}')
    body = xor_seed(raw[:n + 4], struct.pack('<I', seed))
    length = struct.unpack('<I', body[n:])[0]
    return b''.join(dec_block(rk, body[i:i + 16]) for i in range(0, n, 16))[:length]


def decrypt_fw(rk, raw):
    n = len(raw) // 16 * 16
    body = xor_seed(raw[:n], raw[n:n + 4])
    pt = b''.join(dec_block(rk, body[i:i + 16]) for i in range(0, n, 16))
    if pt[:16] != bytes(16):
        raise ValueError('block 0 did not decrypt to zeros')
    return pt


def encrypt_fw(rk, pt, seed):
    return xor_seed(b''.join(enc_block(rk, pt[i:i + 16]) for i in range(0, len(pt), 16)), seed) + seed


def selftest():
    rk = expand(bytes(range(16)))
    ct = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    assert enc_block(rk, bytes.fromhex('00112233445566778899aabbccddeeff')) == ct
    assert dec_block(rk, ct) == bytes.fromhex('00112233445566778899aabbccddeeff')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Decrypt Bloody7 encrypted config files and .sn8encode5 firmware')
    ap.add_argument('file', nargs='?', default='dyn/ini/UsbID.txt')
    ap.add_argument('-o', '--out', help='write raw plaintext here (firmware default: FILE.bin)')
    ap.add_argument('--exe', default=os.environ.get('BLOODY7_EXE', 'dyn/Bloody7.exe'), help='your Bloody7.exe, read only when the key cache is missing')
    a = ap.parse_args()
    selftest()
    rk = load_key(a.exe)
    raw = open(a.file, 'rb').read()
    if a.file.endswith('.sn8encode5'):
        pt = decrypt_fw(rk, raw)
        assert encrypt_fw(rk, pt, raw[-4:]) == raw, 'round-trip re-encrypt mismatch'
        open(a.out or a.file + '.bin', 'wb').write(pt)
        sys.exit()
    pt = decrypt_config(rk, raw)
    if a.out:
        open(a.out, 'wb').write(pt)
    sys.stdout.write(pt.decode('utf-16-le') if pt[1:2] == b'\0' else pt.decode('latin-1'))
