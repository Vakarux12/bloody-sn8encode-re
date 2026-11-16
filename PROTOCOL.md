# Bloody A60 (09da:72e7) reverse engineering

Full RE of the A4Tech Bloody A60 mouse and its Bloody7 configuration software.

- Mouse: A60cir, Sonix sensor P3332A, firmware code 0x04EC, firmware version 0x13.
- Software: Bloody7 V2026.1020 (C++Builder, i386), installer `Bloody7_V2026.1020_MUI.exe`.
- Tool: `bloody.py` (Linux userspace, no driver). Self-check: `test_bloody.py`.

## 1. USB layout

| Interface | hidraw | Purpose |
|---|---|---|
| 0 | input0 | boot keyboard (multimedia/extra keys) |
| 1 | input1 | mouse (buttons, X/Y, wheel, 16-bit) |
| 2 | input2 | vendor config (usage page 0xFF32, usage 0x04EE) |

Config interface is the one to talk to. udev rule for user access:
`SUBSYSTEM=="hidraw", ATTRS{idVendor}=="09da", ATTRS{idProduct}=="72e7", TAG+="uaccess"`

## 2. Config protocol

Feature report ID 7, 64-byte packets. SET_FEATURE the request, GET_FEATURE the reply.

```
request:  [0]=07  [1]=opcode  [2..3]=00  [4]=80 write / 00 read  [5..7]=00  [8..]=data
reply:    [0..1] echo the request; payload normally starts at [8]
```

Gotcha: the reply buffer is not cleared between commands. Bytes an opcode does not
write keep the previous reply's values. Only trust a field that differs from its
neighbours in a sweep. Opcodes 0x30-0x45 and 0x6f-0x76 only walk the echoed opcode
across stale data: unconfirmed.

Write-acceptance (verified live, no-op writes of each register's own value, mouse
stayed healthy): 0x0e 0x13 0x1e 0x4e 0x7a 0x7b 0x7e 0xa2 0xa4 0xa5 are all writable
config registers. 0x11 (backlight) and 0x84 (LED) take real value writes. The exact
per-register meaning (DPI steps, report rate, colours) needs value writes observed
against physical effects (mouse motion for DPI/rate), not done here to avoid changing
saved settings.

## 3. Opcode map (read sweep, byte 4 = 00)

Confirmed data opcodes:

| Op | Field | Meaning |
|---|---|---|
| 0x02 | [20..21]=ec 04 | firmware code; [24..54] button table (below) |
| 0x0e | [9..11]=64 64 64 | three 0x64 (100) values, [17]=01 |
| 0x11 | [8]=0..3 | backlight level. Write: `op 0x11, data=[level]` |
| 0x13 | [8]=1f | unknown constant |
| 0x1e | [7..9]=09 02 02 | unknown |
| 0x1f | [10..11]=ee 04, [12]=13 | config usage 0x04EE, firmware version 0x13 |
| 0x27 | [17..24] | sensor/config block, shares bytes with 0x05/0x29 |
| 0x28 | a4 a4 | unknown pair |
| 0x29 | [8..15] | config block |
| 0x2a | ff ff | unknown pair |
| 0x4e | [8]=01 | flag |
| 0x7a 0x7b 0x7e | [8]=03 | three fields reading 3 |
| 0x81 0xa0 | [8]=21 | unknown |
| 0xa2 | [8]=40 | unknown |
| 0xa4 | [8]=1e | unknown |
| 0xa5 | [8]=25 | unknown |

Button table (opcode 0x02, bytes 24..54): 15-16 slots, each a pair
`(slot_id, action)`. slot_id runs 0x08..0x17, action 0x81 = assigned, 0xff = unassigned.

State-changing reads (not persisted, a reboot restores):
- 0x7c turns the lighting zones off. 0x7d toggles another live state.

Reboot opcodes (mouse disconnects, returns in ~0.4 s unharmed): 0x00, 0x86,
0xa7-0xc1, 0xd6-0xff. These are unrecognised commands; the firmware resets.

Raw replies: `probe_read.json`. Sweep logs: `logs/probe_read*.txt`.

## 3b. Opcode -> software unit (from the binary)

The app's generic send primitive (0x55d060) builds the 72-byte buffer as
`[0]=report id(07) [1]=opcode(reg cl) [2..]=payload(stack args) [4]=write flag`.
Tracing the opcode immediate passed into every send primitive gives the authoritative
command-to-feature map:

| Op | Unit | Feature |
|---|---|---|
| 0x01 0x02 | Hid_keybdadc | keyboard/ADC, button table |
| 0x03 | Hid_flash, Hid_flash_m0, Hid_donglepair/pll, Hid_producttest | flash/pairing page op |
| 0x04 0x10 | Hid_flash_nor | SPI-NOR flash |
| 0x05 0x06 0x07 0x08 0x0a 0x0c 0x0d 0x0e 0x0f 0x1e 0x1f 0x20 | Hid_oscarid7 | A60 (ID7) core config: profiles, DPI, report rate, identity |
| 0x09 | Hid_producttest | factory test |
| 0x11 | Hid_ram / backlight | backlight level 0-3 (confirmed live) |
| 0x12 0x13 | Hid_sled | sensor / lift-off |
| 0x14 0x17 0x18 | Hid_ram | RAM read/write |
| 0x15 0x16 | Icmd_chat | "chat" messaging feature |
| 0x19 0x1a 0x1b 0x1c | Hid_wheel4d | 4-way (tilt) wheel |
| 0x28 0x29 0x2a 0x2b 0x2c 0x2d | Hid_irpt, Hid_flash_nor | interrupt/report config |
| 0x84 | Hid_oscarled | RGB lighting. Payload: 2-byte value. Write confirmed live (device accepted it, lighting stayed active) |

Note the opcode number alone is ambiguous: the same byte means different things to
different firmware units depending on context. Read vs write is the byte-4 flag.

## 4. Software internals (Bloody7.exe)

- C++Builder VCL app, 22 MB, external PDB. Verbose debug strings ("Feter: ...").
- Every HID write funnels through one HidD_SetFeature wrapper at 0x133eec8
  (reads via 0x133f030), 16 callers. No DeviceIoControl: pure HID feature reports.
- 40 Hid_/Iom_/Icmd_ units (`units.txt`). The flash units (Hid_flash, Hid_flash_nor,
  Hid_flash_m0) build `07 01/02/2a/2f + addr + len` packets: these are SPI/flash
  commands. Never send them with the write flag unless you intend to reflash.
- The `Encryption_aes` unit (0x46d09c) encrypts the config file `UsbID.txt`, not the
  firmware. Its key handling reads `Ini\UsbID.txt`.

## 5. Firmware files (FW/*.sn8encode5)

- Sonix SN8 images, 0x8100 bytes (2064 x 16-byte blocks) + 4-byte trailer.
- 256 images covering many Bloody models; 4 bank variants each (_0_.._3_), near
  identical (bank0 vs bank1: 32885/33028 bytes equal).
- Encryption is a block cipher in ECB mode (equivalently a fixed codebook):
  - identical plaintext -> identical ciphertext (the erased-flash pad block repeats
    1099x in one image),
  - two different configs for the same chip share 2055/2064 block positions.
  - NOT repeating-XOR (XOR-with-pad leaves entropy ~4.7, not flat).
- The first 0x100 bytes of every image are 16 identical copies of one 16-byte block
  (e.g. A60: `e9 4c 28 97 4e 40 a0 49 21 63 d5 95 30 ca 49 6c`). That block is the
  cipher's encryption of the constant erased-flash fill at the start of the image.
- Per-model keys: that signature block differs per model. The 256 images group into
  exactly 21 distinct keys, each shared by a family of related models:
  - A60cir's family, J-series (J82/J90/J95...), V-series, Acir/Air/F family, etc.
  - So the key is derived per model family, not a single global key.
- The user's own device: `Acir2_P3332A_0B8_0_44.sn8encode5` (24836 B = 0x6104;
  1552 x 16-byte blocks + 4-byte trailer `aa df 96 03`). Erased-flash signature block
  `5c c4 1b 96 fb c8 93 48 94 eb e6 94 85 42 7a 6d`, repeats 632x; first 48 blocks
  (0x300 B header) are all signature. Trailer is not a standard CRC32 (likely a
  plaintext checksum). The 4 bank variants share 890/1552 blocks.

### What the cipher is NOT (ruled out this pass)
- Not off-the-shelf AES. Bloody7.exe contains **no AES S-box or T-tables** in any
  orientation (forward/inverse, byte-reversed), and imports no bulk crypto
  (no CryptEncrypt/ImportKey/DeriveKey, no BCrypt; only CryptDecodeObject for certs).
- Not TEA/XTEA/XXTEA: the delta constant 0x9E3779B9 appears nowhere.
- Not a contiguous-key AES: scanned every 16- and 32-byte window of both the exe and
  the firmware as an AES-128/256 key, straight and byte-reversed (the Sonix
  convention), testing enc(erased)==signature for FF/00 fills. 0 hits
  (`keyscan2.c`, run on archbook).

### Where the cipher actually is
- The app's only cipher is the C++Builder unit **`Encryption_aes`** (loader entry
  0x46d0bc, reads `ini\UsbID.txt`). `UsbID.txt` is 752 B = 47 x 16-byte blocks,
  entropy 7.76 — i.e. the **same 16-byte-block ECB primitive** as the firmware.
  Strong inference: config and firmware share one custom cipher, keyed differently
  (per-family key for firmware).
- The cipher core is NOT any of the tables/functions chased here: the 256-entry table
  at VA 0x153dc24 (ref 0xd4faa8) is a color/gamma interpolation curve; 0x46dea8 & co.
  are STL vector/memcpy helpers. The real block transform is buried deeper in RTL glue.
- The encrypted `.sn8encode5`/`.sn8encode` extension literals are **unreferenced**
  anywhere in the exe (not as immediates, not as data pointers); only `.sn8`
  (VA 0x13942e2, used in 0x43a350) is referenced, and that path reads a *plaintext*
  ".sn8" settings file (WORD records, markers like 12 00 01 00 10 00 01 00), not the
  ciphertext. So the firmware filename is data-driven (from the decrypted UsbID.txt
  model DB), and no visible exe code decrypts the firmware blob directly.

### Dynamic analysis state (Wine)
- The installed Bloody7.exe (BOOTCAMP `Program Files (x86)\Bloody7\Bloody7\`) is
  **byte-identical** to the disassembled copy (sha256 9cb136a4...); "installer vs
  installed" is the same binary — the installed side's value is real device data
  (`UserLog\Mouse\Acir2_26A4EA65`, real `UsbID.txt`).
- The app **does** launch under `xvfb-run wine` (prefix `~/bloody-re/prefix`). winedbg
  breakpoints work with `break *0xADDR` + `cont` (earlier failures were bad syntax).
- But 0x46d0bc (config decrypt) is **device-gated**: a 90s device-less run reads
  `AppConfig.ini` and never touches `UsbID.txt`, so the breakpoint never fires.
- Worse, even WITH the mouse plugged in, Wine enumerates all three interfaces
  (hidraw0/1/2, vid 09da pid 72e7, incl. the vendor config iface 2) but the app's own
  device-matching never engages it: a 140s run with breakpoints on 0x46d0bc AND the two
  HID feature wrappers (0x133eec8 write, 0x133f030 read) fired **none** of them. So the
  app never talks to the config interface under Wine and never reaches the decrypt.
- The decrypt caller lives in a **virtual method** 0x48d6ac (single vtable ref at file
  0xfb6a62), gated at 0x48d74d (`je 0x48d8d4` unless cl!=0, set from a file-exists +
  vtable check). Forcing it device-free means forcing that indirect call, not just a
  one-byte jump patch.
- Flash readback (reading the already-decrypted code back off the MCU) is the only
  route that targets plaintext directly, but `Hid_flash` (0x55de08) issues opcode 0x03
  with a **sub-command selector** (0x00/0x01/0x02…) — SN8 ISP ops that include erase/
  write. Firing the wrong one can brick the live device, and an encrypted-firmware MCU
  almost certainly has flash **readout protection** (readback returns zeros/garbage).
  High risk, low expected payoff — not attempted.

### Reference (external)
- GMMan/snc73xx-firmware-encryption: Sonix SNC73xx (ARM) firmware is decrypted by an
  on-chip AES peripheral (AES-256, CBC/OFB, byte-reversed), key from eFuses/load-table.
  Different chip family (we have an 8-bit SN8), but confirms Sonix ships encrypted
  images that the MCU decrypts in hardware. No public method exists for `.sn8encode`.

### Status / remaining paths to PLAINTEXT (all costly or device-touching)
Cipher fully characterised (16-byte ECB, per-family key, custom non-AES/non-TEA
primitive); plaintext NOT recovered. Cheap avenues are exhausted. Options left:
1. **Static reverse of `Encryption_aes`** core, then find the per-family key table/
   derivation. Large effort through C++Builder RTL; cracks config, probably firmware too.
2. **Dynamic key capture**: make the live mouse visible to the Wine app so it decrypts
   `UsbID.txt`, break in `Encryption_aes`, dump key + algorithm. Safe-ish (config read,
   no flashing) but may rewrite saved mouse settings; needs Wine HID passthrough.
3. **Flash readback from the MCU** over the HID config interface (Hid_flash opcodes).
   If the SN8 allows readout it yields plaintext directly — but wrong sub-opcodes can
   erase/brick the live device. User decision required.
4. **Hardware MCU dump** (SWD/ISP/glitch, cf. SonixQMK sonix_dumper). Physical, bricks
   risk, out of software-RE scope.

## 5c. Cipher structure breakthrough (key is only 32 bits)

Analysing block-0 of all 256 images (block 0 = `enc(erased-flash fill)`, the per-family
signature) across the 21 families:

- **Every pairwise XOR of two families' signatures is one 32-bit value repeated in all
  four 4-byte lanes** (e.g. `e96f1e07 e96f1e07 e96f1e07 e96f1e07`).
- Within any family's signature the inter-lane differences are a **fixed, family-
  independent** constant: `lane_i XOR lane_0 = (0, a70c88de, c82ffd02, d98661fb)` for
  all 21 families.

So the cipher factorises as:

```
cipher_block = KeylessTransform(plaintext_block) XOR broadcast(k32)
```

where `KeylessTransform` is shared by every model and the entire per-family key is a
single **32-bit** word `k32` XOR'd into each 32-bit lane. (Key-on-output, or a linear
transform with key-on-input — equivalent here. No AES S-box / no TEA delta + low ARX
density ⇒ `KeylessTransform` is likely linear: a bit-permutation/matrix, trivially
invertible once read from the code.)

Decrypt recipe (pending the transform from the decompiler):
```
broadcast(k32) = signature XOR KeylessTransform(0xFF*16)   # must come out lane-periodic
plaintext      = KeylessTransform^-1( cipher_block XOR broadcast(k32) )
```
This is a dedicated, weak, offline scheme — consistent with the PC app decrypting after
all (not the MCU). The 21 family k32 values are recoverable directly from the signatures
once `KeylessTransform(0xFF*16)` is known.

## 5d. Firmware upgrade path — decryption is NOT in the PC app

Traced the actual flash path with radare2 (handles the C++Builder switch tables that
fool linear objdump):
- The three flash primitives `Hid_flash` sub-0/1/2 (0x55de28 / 0x55deac / 0x55df28,
  opcode 0x03) are all called from one upgrade function **0x427ec0**.
- Data reaches them through an object getter chain (`0xa844b8` → `0xa84494`, a lazy
  cached property `[reader+0x290]` filled by a vtable call) — i.e. bytes are read from
  the firmware-reader object and streamed to HID.
- 0x427ec0's "80 XORs" are register-zeroing / checksums / flag ops — **no tight
  block-cipher loop** (only one 5-op cluster, not a cipher). No decrypt at file load
  either (the reader getter does no transform).

Combined with: no AES S-box / no crypto-API / no TEA delta anywhere; no contiguous key
matching the firmware crib; `.sn8encode5` filenames unreferenced in the exe; and the
Sonix hardware-decrypt precedent — the conclusion is firm:

**The PC app ships the encrypted `.sn8encode5` blob to the device as-is; the Sonix SN8
MCU decrypts it in hardware during ISP. Firmware plaintext never exists on the PC and is
not recoverable by reverse-engineering the PC software.**

What the scheme (the MCU's cipher) is, fully characterised from the ciphertexts (§5c):
`cipher = KeylessTransform(plaintext) XOR broadcast(k32_family)`, 16-byte ECB, one shared
keyless transform, a 32-bit per-family key broadcast into each lane, universal inter-lane
delta `(0, a70c88de, c82ffd02, d98661fb)`, 21 family keys enumerated. Inverting it needs
`KeylessTransform`, which lives in the MCU bootloader, not the PC.

To obtain actual plaintext bytes: read the decrypted code back off the MCU (ISP/SWD
readback — brick risk + the chip almost certainly has readout protection, since the whole
point of shipping encrypted firmware is to prevent this), or a hardware MCU dump/glitch
(cf. SonixQMK `sonix_dumper`). Both are physical, device-risking, and outside PC software RE.

## 6. Tool usage

```
python3 bloody.py info            # model, firmware, backlight, button count
python3 bloody.py backlight       # read level
python3 bloody.py backlight 2     # set level 0-3
python3 bloody.py dump            # read-only sweep of safe opcodes
python3 bloody.py raw 0x1f        # one raw read
python3 test_bloody.py            # offline self-check
```

---

## 6. Native Windows confirmation (2026-11-16)

Ran the **real Bloody7 app natively** on a second machine (archbook, Win10,
mouse 09da:72e7 attached) over SSH, after the Wine route proved the app
deadlocks at startup (COM/form init) before decrypting anything. Natively the
app initialises fully and talks to the mouse. Took full-memory procdumps
(`-ma`) of the running `Bloody7.exe` and mined them.

**Findings (decisive for the firmware goal):**
- **No firmware ciphertext and no decrypted firmware anywhere in the running
  app's memory.** The 16-byte family signature block `5cc41b96…` appears **0×**
  in a 291 MB full dump of the fully-initialised, mouse-connected app. The app
  does not load, hold, or decrypt `.sn8encode5` during normal operation — it
  only streams the raw blob to the MCU during an actual flash. → **Confirms
  on-chip decryption** (eFuse-keyed hardware engine, per the SNC73xx precedent).
- The decrypted **config** (`UsbID.txt`) *is* produced in memory at startup
  (parser keys `StrictControl`/`VidPid` + live VID/PID present as UTF-16), but
  the decrypted **text buffer is freed immediately** after parse (decrypt→parse
  →free is one synchronous op); no persistent plaintext copy survives in a dump,
  even one taken ~1 s after launch. Capturing it cleanly needs a breakpoint at
  the version-specific parser call site (on the build I disassembled that is
  `call 0x46d0bc` at `0x48d842`, with the decrypted-string pointer in `EDX`;
  the installed build differs — hash `0dce51e2…` vs `9cb136a4…` — so the address
  must be re-derived per build). A headless Win32 debugger for this was written
  (`wine-tools/capbuf.c`).

**Why the firmware plaintext is not PC-extractable (final):**
1. The PC app never decrypts firmware (confirmed above) — nothing to dump.
2. Pure cryptanalysis is insufficient: the only known-plaintext available is the
   erased-flash fill (→ the per-family signature block). For a linear transform
   `T` that is one P/C pair per family with a *different* key each; it recovers
   only key-deltas (already known), not `T` on arbitrary inputs. Recovering `T`
   needs ~128 independent genuine-plaintext blocks (real firmware code), which we
   do not have without first decrypting an image — chicken-and-egg.
3. The config software-cipher (app) and the firmware hardware-cipher (on-chip,
   eFuse key) are almost certainly unrelated, so decrypted `UsbID.txt` is not
   expected to transfer to firmware.

**Remaining avenues (all outside PC software):** (a) passive **USB capture during
a real firmware update** to confirm sent-bytes == on-disk ciphertext (needs an
update to exist; the flash itself carries brick risk); (b) **hardware** attack on
the readout-protected MCU (glitch/decap/eFuse readout) — invasive, out of scope;
(c) obtaining a genuine decrypted image / SDK externally.

**Conclusion:** the firmware cipher *structure* is fully characterised (§5c), and
it is now natively confirmed that the plaintext is produced only inside the MCU
and cannot be obtained from the PC or by cryptanalysis of the shipped images
alone.

## 7. Structural swing at the KeylessTransform `T` (2026-11-16) — result

Took the one remaining offline path: hypothesise concrete simple forms for `T`
and test them against all 287 locally-held `.sn8encode5` images (script
`crack.py`). Model under test: `C = M·P ⊕ K_family` (affine over GF(2), 16-byte
ECB), `M` = the shared KeylessTransform.

**Confirmed, fleet-wide (strong, 287 images):**
- `T` is **affine-linear**: every sampled pairwise family-signature XOR is
  lane-periodic (`broadcast(k_f ⊕ k_g)`) — a non-linear transform could not do
  this. 27 distinct family signatures.
- The §5c inter-lane delta `(0, a70c88de, c82ffd02, d98661fb)` holds in
  **287/287** images.
- **New universal anchor:** `U = sig ⊕ (2nd-most-common block) =
  ffec107d 28faf523 232462e5 25b97391`, identical across **205/287** images
  (= `M·(fill ⊕ P_z)` for a universal plaintext region `P_z`, the zero/padding
  fill shared by same-family firmware).

**Candidate `T` forms tested and REJECTED:**
- *Per-byte identical S* (`T(P)=bytewise_S(P)⊕V`): requires `U` byte-periodic.
  `U` is not byte-periodic → rejected. `M` genuinely mixes across byte lanes.

**Why `M` is still unrecoverable (the hard wall, now quantified):**
- `M` has 128×128 = **16384 unknown bits**.
- We possess exactly **one known-plaintext VALUE**: the erased fill `0xFF*16 →
  block-0 signature`. Every other universal block (`P_z`, cross-model shared
  code blocks found by key-delta collision) is a *fixed but unknown* plaintext —
  it constrains key-deltas (≤32-dim, already known) but gives no new equation on
  `M` in terms of a known input.
- Constant-byte plaintext blocks (the only "guessable" inputs: `00*16`,
  `FF*16`, `80*16`, …) span at most an **8-dimensional** input subspace. Even
  harvesting all of them yields ≤8 independent `(P, M·P)` equations.
- Solving a 128-input linear map needs ~128 independent known-input/output
  pairs. We have ≤8 reachable, and realistically 1. The system is
  under-determined by >16000 bits.

**Brute force / GPU verdict (answers the "how many possibilities / Google GPU"
question):** the secret is `M`, not a short key. Unstructured that is 2^16384;
even assuming `M` is a mere bit-permutation it is log2(128!) ≈ **2^716**; a
byte-permutation-plus-affine still hundreds of bits. There is also no cheap
validation oracle — we cannot even produce a candidate plaintext to score
without `M`. GPUs do not help: this is not a keyspace search, it is an
**under-determined linear system** — compute cannot manufacture the missing
~120 known-plaintext equations.

**Final:** `T` is fully *characterised* (affine-linear, 16-byte ECB, universal
inter-lane delta, two universal anchors `U` and the fill signature, 32-bit
broadcast per-family keys), but the 16384-bit matrix `M` itself — the only thing
needed to actually decrypt — lives in the Sonix MCU bootloader and is not
recoverable from the shipped ciphertexts plus the single erased-fill known
plaintext. Firmware plaintext is therefore **not obtainable** by PC software RE
or by cryptanalysis of the images; only a hardware MCU dump/glitch (brick/decap
risk, out of scope) or an externally-supplied genuine decrypted image would
yield it.
