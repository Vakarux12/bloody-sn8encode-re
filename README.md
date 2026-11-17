# A4Tech Bloody (Sonix SN8) reverse engineering

Reverse engineering of A4Tech **Bloody** mice and the **Bloody7** configuration
software, from Linux. This repo documents three things:

1. **The vendor HID config protocol**, usable with no driver. A small Linux userspace
   tool (`bloody.py`) reads model/firmware info, sets backlight, and sweeps the opcode
   map over HID feature report 7.
2. **The Bloody7 file cipher, solved.** Config and data files (`ini/UsbID.txt`, macro
   and gun scripts) are AES-128-ECB with one key hardcoded in Bloody7.exe.
3. **The `.sn8encode5` firmware cipher, solved.** It is the same AES-128 key and cipher.
   All 287 firmware images shipped with Bloody7 decrypt to Sonix SN8 machine code.

Target device during this work: **Bloody A60cir / Acir2, USB `09da:72e7`, Sonix SN8 MCU,
sensor P3332A**. The protocol findings generalise across the Bloody7 lineup.

Full writeup: **[`PROTOCOL.md`](PROTOCOL.md)**, cipher details in section 8.

## The cipher, in one paragraph

```
file_block = AES-128-ECB_K(plaintext_block) XOR broadcast32(seed)
```

`K` is 16 bytes stored as 16 dwords at VA `0x154ad54` in Bloody7.exe, next to an AES
S-box that is also stored one byte per dword. That layout is why byte-level S-box and
key scans never found it. `seed` is a random 28-bit nonce from `srand(time)/rand()` and is
stored **in clear**: it is the 4-byte trailer of each `.sn8encode5`, and the second word of
the 16-byte `len|seed|version|crc32` trailer of config files. The repeated block at the
start of every firmware image is `AES_K(0x00 x 16)` XOR the seed. Its lane structure is the
"universal inter-lane delta" `(0, a70c88de, c82ffd02, d98661fb)` from the earlier analysis.

```sh
python3 decode_config.py path/to/ini/UsbID.txt                # prints the INI text
python3 decode_config.py path/to/X.sn8encode5 -o X.bin        # raw SN8 image
python3 sn8dis.py SN8F2288 X.bin X.asm                         # any SN8 disassembler
```

The key is cached in `bloody7.key`. If that file is missing, `decode_config.py` pulls the key
from your own copy of Bloody7.exe (`--exe path/to/Bloody7.exe`) and checks it against the
firmware check value before use.

### What was wrong before

The earlier writeup (sections 5 to 7, kept as a research log) concluded that the firmware
transform was an unknown affine-linear 128x128 matrix living only in the MCU. Two wrong
assumptions caused that:

- **Wrong fill.** The erased-fill plaintext was taken as `0xFF x 16`, but it is `0x00 x 16`.
- **Wrong crib.** The AES key scan demanded `AES_K(fill) == signature`. The seed XOR always
  breaks that match. The right test is "`AES_K(fill) XOR signature` is lane-periodic"
  (`keyscan3.c`).

Lane-periodic family XORs prove only that the key is applied on the output. They do not prove the
transform is linear. The PC still ships the encrypted blob to the device unchanged, so the
MCU's bootloader does the decrypting, but with the app's own key.

## Tools

| File | What it does |
|---|---|
| `decode_config.py` | Pure Python, no dependencies. Decrypts Bloody7 config/data files and `.sn8encode5` firmware, and re-encrypts firmware (round trip verified on every image). |
| `bloody7.key` | Cached AES-128 key (hex). Delete it to re-derive the key from your Bloody7.exe. |
| `bloody.py` | Linux userspace tool for the live mouse (info, backlight, opcode sweep, raw). No driver, talks HID feature report 7. |
| `test_bloody.py` | Offline self-check for `bloody.py`'s packet builder. |
| `analyze_fw.py` | Block-structure analyzer for `.sn8encode*` images (signatures, repeats, trailers). |
| `keyscan3.c` | AES key scanner with the correct crib (contiguous and 16/32-bit strided keys). |
| `crack.py`, `keyscan2.c` | Historical. The structural analysis and exact-match key scan behind the old conclusion. |
| `units.txt` | The 40 `Hid_/Iom_/Icmd_` firmware units recovered from the binary, with addresses. |
| `probe_read.json` | Raw replies from the live-device opcode sweep. |

```sh
# live mouse (plug in a Bloody, add the udev rule in PROTOCOL.md section 1 for non-root)
python3 bloody.py info
python3 bloody.py dump
```

## Firmware images are NOT included

The `.sn8encode5` blobs and their decrypted plaintexts are A4Tech's copyrighted files and
are **not redistributed here**. Get them from the official **Bloody7** installer
(`Bloody7_V2026.xxxx_MUI.exe`) from a4tech.com. After install they live under
`...\Bloody7\FW\**\*.sn8encode5`.

## Scope and ethics

This is interoperability and security research on hardware the author owns. Nothing here
flashes or modifies device firmware. Writing a modified image to a mouse can brick it, and
the integrity check the bootloader applies is not yet understood.

## License

Code and docs in this repo: MIT (see `LICENSE`). Does not cover A4Tech firmware, which is
not included.
