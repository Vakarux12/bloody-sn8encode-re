# A4Tech Bloody (Sonix SN8) reverse engineering

Reverse engineering of A4Tech **Bloody** mice and the **Bloody7** configuration
software, from Linux. Two things are documented here:

1. **The vendor HID config protocol**, fully usable with no driver needed. A small
   Linux userspace tool (`bloody.py`) reads model/firmware info, sets backlight,
   and sweeps the opcode map over HID feature report 7.
2. **The `.sn8encode5` firmware cipher**, structurally cracked but **not yet
   invertible**. This is the open problem. See below if you want to continue it.

Target device during this work: **Bloody A60cir, USB `09da:72e7`, Sonix SN8 MCU,
sensor P3332A**. The protocol findings generalise across the Bloody7 lineup. The
cipher analysis covers all 287 `.sn8encode5` images shipped in Bloody7.

Full writeup: **[`PROTOCOL.md`](PROTOCOL.md)**.

## The firmware cipher, in one paragraph

Each `.sn8encode5` image is a Sonix SN8 firmware encrypted as **16-byte ECB**:

```
cipher_block = M · plaintext_block  XOR  broadcast(k32_family)
```

- `M` (the "KeylessTransform") is an **affine-linear 128x128 GF(2) transform shared
  by every model**, confirmed fleet-wide: every pairwise family-signature XOR is
  lane-periodic, which a non-linear map could not produce.
- The entire per-family key is a single **32-bit word** `k32`, broadcast into each
  of the four 32-bit lanes.
- Universal, family-independent inter-lane delta of the erased-fill signature,
  `lane_i XOR lane_0 = (0, a70c88de, c82ffd02, d98661fb)`, holding in **287/287**
  images.
- Second universal anchor: `U = sig XOR (2nd-most-common block) =
  ffec107d 28faf523 232462e5 25b97391` (205/287 images).

### Why it is not yet decryptable (the open problem)

Inverting the scheme needs `M`, which is 16384 unknown bits. Recovering a 128-input
linear map requires about 128 independent **known-plaintext** blocks. We have
exactly **one** known-plaintext value, the erased-flash fill `0xFF*16`, which
encrypts to the per-family signature block. Constant-byte blocks (the only other
"guessable" inputs) span at most an 8-dimensional subspace. So the system is
under-determined by over 16000 bits, and brute force is hopeless (the secret is a
matrix, not a short key, so roughly 2^716 even if `M` is merely a bit-permutation).
Independent evidence (a memory dump of the running app, and disassembly of the
upgrade path) shows the **PC software never decrypts firmware**. The SN8 MCU almost
certainly decrypts on-chip with an eFuse-held key, matching the Sonix SNC73xx
precedent. Details and dead-ends are in `PROTOCOL.md` sections 5 to 7.

### How to continue

The one thing that breaks it wide open: **a single genuine decrypted image** (or
any ~128 independent known-plaintext/ciphertext block pairs). With that, `crack.py`
can be extended to solve `M` by Gaussian elimination over GF(2), and every image in
that family then decrypts. Candidate sources of known plaintext:

- A hardware MCU dump/glitch of the SN8 (cf. SonixQMK `sonix_dumper`). Invasive,
  risk of bricking, out of scope here.
- A leaked or official decrypted image or SDK.
- Any structural insight that pins `M` with fewer than 128 equations. The
  per-byte-matrix form is already **ruled out**, because `U` is not byte-periodic.

Issues and PRs welcome if you get further.

## Tools

| File | What it does |
|---|---|
| `bloody.py` | Linux userspace tool for the live mouse (info, backlight, opcode sweep, raw). No driver, talks HID feature report 7. |
| `test_bloody.py` | Offline self-check for `bloody.py`'s packet builder. |
| `analyze_fw.py` | Block-structure analyzer for `.sn8encode*` images (signatures, repeats, trailers). |
| `crack.py` | Fleet-wide cipher structural analysis (the section 7 result): confirms affine-linearity, the universal deltas and anchors, and quantifies why `M` is under-determined. |
| `keyscan2.c` | Brute scanner that tried every 16/32-byte window of the exe and firmware as an AES key (straight and byte-reversed). Zero hits, so AES is ruled out. |
| `units.txt` | The 40 `Hid_/Iom_/Icmd_` firmware units recovered from the binary, with addresses. |
| `probe_read.json` | Raw replies from the live-device opcode sweep. |

```sh
# live mouse (plug in a Bloody, add the udev rule in PROTOCOL.md section 1 for non-root)
python3 bloody.py info
python3 bloody.py dump

# firmware images (get them from the official Bloody7 installer, see below)
python3 analyze_fw.py path/to/*.sn8encode5
python3 crack.py        # expects the FW/ tree next to it, edit the glob paths
```

## Firmware images are NOT included

The `.sn8encode5` blobs are A4Tech's copyrighted files and are **not redistributed
here**. Get them yourself from the official **Bloody7** installer
(`Bloody7_V2026.xxxx_MUI.exe`) from a4tech.com. After install they live under
`...\Bloody7\FW\**\*.sn8encode5`. `crack.py` and `analyze_fw.py` take them as input.

## Scope and ethics

This is interoperability and security research on hardware the author owns. It does
not distribute vendor firmware or any working decryptor (none exists, that is the
open problem). Nothing here flashes or modifies device firmware.

## License

Code and docs in this repo: MIT (see `LICENSE`). Does not cover A4Tech firmware,
which is not included.
