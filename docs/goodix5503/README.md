# Goodix 27c6:5503 driver for libfprint

Documentation of the work needed to make the Goodix `27c6:5503` fingerprint
reader (Lenovo IdeaPad 3 15ITL6 / 82H8) work with libfprint and fprintd on
Linux, including login and `sudo` through PAM.

There was no driver for this PID. It was built from two sources: the reverse
engineering script `driver_5503.py` from
[goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)
(which defines the protocol), and the libfprint driver
[AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)
(commit `309d4c6`) for the 5335/5385/5395 chips, which provided the
architecture (state machines, libfprint integration and SIGFM matching). The
protocol of that template turned out **not** to be the 5503's, so almost all
of the transport, session and capture code was rewritten.

This document explains what the driver does, how each piece was discovered,
which measurements back each decision, how to build, test and install it, and
what is left to do.

---

## Contents

1. [Current status](#1-current-status)
2. [Hardware](#2-hardware)
3. [Code layout](#3-code-layout)
4. [5503 USB protocol](#4-5503-usb-protocol)
5. [Finger detection](#5-finger-detection)
6. [Image and matching](#6-image-and-matching)
7. [Build, test and install](#7-build-test-and-install)
8. [fprintd, PAM and the login screen](#8-fprintd-pam-and-the-login-screen)
9. [Dual boot with Windows (PSK)](#9-dual-boot-with-windows-psk)
10. [Environment variables](#10-environment-variables)
11. [Security](#11-security)
12. [Limitations and future work](#12-limitations-and-future-work)
13. [Project history](#13-project-history)
14. [Analysis tools](#14-analysis-tools)
15. [References](#15-references)

---

## 1. Current status

| Feature | Status |
|---|---|
| Device open (USB, PSK, TLS, configuration) | Works |
| TLS-PSK handshake with the sensor | Works (TLS 1.2, `PSK-AES128-CBC-SHA256`) |
| Image capture and decryption (64×80, 12-bit) | Works |
| Finger down / finger up detection | Works, by polling the sensor zones (section 5) |
| Enroll (8 samples) | Works |
| Verify / identify (SIGFM) | Works; see accuracy in 6.4 |
| fprintd + PAM (`sudo`, login) | Works |
| Dual boot with Windows | Works, rewriting the PSK automatically (section 9) |
| Lock screen, suspend/resume | Works (unlocking after a suspend tested) |

Measured accuracy (section 6.4): **0 out of 9** attempts with a different
finger were accepted. With the enrolled finger, the centre of the pad is
recognised reliably; the tip and the sides fail if they are not in the
template (the sensor only sees part of the finger).

---

## 2. Hardware

| | |
|---|---|
| Machine | Lenovo IdeaPad 3 15ITL6 (82H8), i7-1165G7 |
| USB | `27c6:5503` "Goodix FingerPrint Device", USB 2.0 high speed |
| Interface | 0, class 255 (vendor specific) |
| Endpoints | `0x01` bulk OUT, `0x82` bulk IN, `wMaxPacketSize` 512 |
| Firmware | `GF3208_RTSEC_APP_10062` (IAP `MILAN_RTSEC_IAP_10027` according to goodix-fp-dump) |
| Chip ID | `0x00220fa6` (bytes `0f a6 00 22` from register 0) |
| OTP | 64 bytes (not interpreted; see 12) |
| Image | 5120 12-bit pixels = 7680 bytes, **64 columns × 80 rows** |

The machine dual-boots Windows, where the official Goodix driver
(3.1.586.580) works. This matters because of the PSK (section 9).

---

## 3. Code layout

The driver keeps the template's name `goodix53x5` (directory, `FP_COMPONENT`
and driver id in meson) and presents itself to the user as **"Goodix 5503"**
(`full_name`). It is an `FpDevice` (not an `FpImageDevice`): it matches inside
the driver with SIGFM and stores "raw" templates in fprintd.

### 3.1 Files (`libfprint/drivers/goodix53x5/`)

| File | Contents |
|---|---|
| `goodix53x5.c` | GObject class, USB id table, `open`/`close`/`enroll`/`verify`/`identify` |
| `goodix53x5-private.h` | Device state, sensor geometry, PSK constants |
| `goodix53x5-proto.c/h` | Message pack and protocol message formats, read reassembly |
| `goodix53x5-transport.c/h` | USB transfers, command sub-SSM (send → ACK → data), drain, hex logging |
| `goodix53x5-commands.c/h` | Named commands (nop, firmware, reset, PSK, TLS, config, FDT, image…) |
| `goodix53x5-session.c/h` | Open SSM, optional PSK write, TLS handshake, reinit after suspend |
| `goodix53x5-tls.c/h` | TLS-PSK server with OpenSSL over memory BIOs |
| `goodix53x5-scan.c/h` | No-finger reference, finger wait (polling), capture, finger-up wait, deactivation |
| `goodix53x5-image.c/h` | 12-bit decoding, diagnostic PGM, 8-bit preprocessing |
| `goodix53x5-enroll.c/h` | Enroll SSM and template assembly |
| `goodix53x5-auth.c/h` | Verify/identify SSM and match decision |
| `goodix53x5-match.c/h` | C wrapper around SIGFM (extraction, serialisation, scoring) |
| `goodix53x5-calibration.c/h` | The 5503 `DEVICE_CONFIG`; the rest is 53x5 OTP/FDT math (unused) |
| `goodix53x5-crypto.c/h` | Leftover 53x5 "GTLS" code (unused on the 5503) |

`libfprint/sigfm/` contains SIGFM (SIFT-based matching with OpenCV), taken
from the template. Build changes: `libfprint/meson.build` (driver sources,
OpenCV, `libsigfm`) and `meson.build` (driver entry with the `openssl` helper).

### 3.2 State machines

Everything is asynchronous on the GLib main loop: each step is a state of an
`FpiSsm` and waits use USB transfers or timers
(`fpi_ssm_jump_to_state_delayed`), never blocking loops.

- **Open** (`session.c`): `USB_RESET` (set_configuration) → `CLAIM_INTERFACE`
  → `DRAIN` → `PING` → `READ_FW_VERSION` → `RESET` → `READ_CHIP_ID` →
  `READ_OTP` → `PARSE_OTP` → `READ_PSK_HASH` → `WRITE_PSK` →
  `VERIFY_PSK_WRITE` → `CHECK_PSK_WRITE` → `TLS_REQUEST` → `TLS_RECV` ⇄
  `TLS_FEED` ⇄ `TLS_SENT` → `TLS_COMPLETE` → `UPLOAD_CONFIG` →
  `SET_DRV_STATE_1` → `SET_DRV_STATE_2` → `POV_IMAGE` → `POV_IMAGE_DONE`.
- **Enroll** (`enroll.c`): `REINIT` → `CAPTURE_REF` → `WAIT_FINGER` →
  `CAPTURE` → `PROCESS` (SIGFM) → `WAIT_FINGER_UP` → `NEXT` (350 ms) ×8.
- **Verify/identify** (`auth.c`): `REINIT` → `CAPTURE_REF` → `WAIT_FINGER` →
  `CAPTURE` → `MATCH` → `FINISH` (finger-up wait on no match, deactivation on
  match).
- **Capture sub-SSMs** (`scan.c`): no-finger reference, finger wait, capture,
  finger-up wait, deactivation (section 5).
- **Command sub-SSM** (`transport.c`): `SEND` → `RECV_ACK` → `VALIDATE_ACK` →
  `RECV_DATA`.

---

## 4. 5503 USB protocol

The source of truth is `driver_5503.py` + `goodix.py` + `protocol.py` from
goodix-fp-dump. The 53x5 template implements a different protocol
("wrapless", the one in `driver_53x5.py`: CDC interface 1, `cmd|1`
continuation chunks, GTLS through `0xFF01…` MCU messages), which the 5503
silently ignores. That was the first blocker (the ping never got a reply).

### 4.1 Message pack

Every transfer is wrapped as:

```
[flags 1][length 2 LE][checksum 1][data…]
checksum = (flags + length_lo + length_hi) & 0xFF
```

| flags | Contents |
|---|---|
| `0xA0` | Protocol message (commands, replies, ACKs) |
| `0xB0` | TLS handshake records |
| `0xB2` | Image data: 9-byte prefix + TLS application-data records |

Writes: the pack is zero-padded to a multiple of 64 and sent as 64-byte
transfers (as in `protocol.py`). Reads: one transfer of up to 64 KiB; if the
pack is longer, reads continue and are concatenated.

### 4.2 Protocol message (inside a `0xA0` pack)

```
[cmd 1][size 2 LE = payload+1][payload…][checksum 1]
cmd      = category << 4 | command << 1
checksum = (0xAA - sum of all previous bytes) & 0xFF, or 0x88 when unused
```

Every command is first answered with an **ACK** (`cmd 0xB0`, payload
`[acknowledged cmd][flags]`, bit 0 = valid) and then, when applicable, by a
reply message with the same `cmd`.

### 4.3 Commands used

| cmd | cat/cmd | Name (goodix.py) | Payload | Reply |
|---|---|---|---|---|
| `0x00` | 0/0 | nop | `00 00 00 00`, checksum `0x88` | optional ACK (usually none) |
| `0xA8` | A/4 | firmware_version | `00 00` | firmware string |
| `0xA2` | A/1 | reset (sensor) | `05 14` (reset_sensor, 20 ms) | `[01][number LE16]` |
| `0x82` | 8/1 | read_sensor_register | `00 00 00 04` | 4 bytes (chip ID) |
| `0xA6` | A/3 | read_otp | `00 00` | 64 bytes |
| `0xE4` | E/2 | preset_psk_read | `07 00 02 bb 00 00 00 00` | `[status][flags LE32][len LE32][hash]` |
| `0xE0` | E/0 | preset_psk_write | flags `0xbb010003` + len + white box (96 B) | `[status]` (0 = ok) |
| `0xD0` | D/0 | request_tls_connection | `00 00` | ACK, then a `0xB0` pack with the ClientHello |
| `0x90` | 9/0 | upload_config_mcu | `DEVICE_CONFIG` (256 B) | `[01]` |
| `0xC4` | C/2 | set_drv_state | `01 00` | ACK only (sent twice, like Windows) |
| `0xD2` | D/1 | mcu_get_pov_image | `00 00` | `[state]` (`0xff`) |
| `0x36` | 3/3 | mcu_switch_to_fdt_mode | 22 B (4.8) | `[02 01][mask 3f 00][6 zones LE16]` |
| `0x20` | 2/0 | mcu_get_image | `01 00 8b 00 84 00 8c 00 88 00` | `0xB2` pack (4.7) |
| `0x32` | 3/1 | mcu_switch_to_fdt_down | 22 B | ACK + an unconditional `0x32` after ~34 ms (5.1) |
| `0xAE` | A/7 | query_mcu_state | `01 00 32` | 2 bytes |

Other goodix.py commands (`0x34` fdt_up, `0xD6` pov_image_check, `0x70`
idle, …) exist but the current driver does not use them.

### 4.4 Open sequence

1. `set_configuration(1)`, claim interface 0 (detaching any kernel driver).
2. **Drain**: read and discard whatever is pending on `0x82` until a 100 ms
   timeout (equivalent to `empty_buffer()` in goodix.py).
3. nop, firmware version, sensor reset, chip ID, OTP.
4. **PSK** (4.5).
5. **TLS handshake** (4.6).
6. `upload_config_mcu(DEVICE_CONFIG)`, `set_drv_state` ×2, `mcu_get_pov_image`.

### 4.5 PSK

The sensor stores a PSK in its flash and encrypts images with a TLS session
based on it. `driver_5503.py` uses the **all-zero 32-byte** PSK; its hash
(`PMK_HASH`) is `81b8ff49…5ee50361`. The driver reads the hash with
`preset_psk_read(0xbb020007)` and compares it with `PMK_HASH` and with
`sha256(PSK)`.

If it does not match, **by default nothing is written**: the driver logs
`PSK mismatch, write skipped - set GOODIX5503_ALLOW_PSK_WRITE=1 to write it`,
continues, and the TLS handshake then fails with a message saying so. Only
with `GOODIX5503_ALLOW_PSK_WRITE=1` does it write the white box of the zero
PSK (`preset_psk_write(0xbb010003, PSK_WHITE_BOX)`) and verify it by reading
the hash again. The write is **persistent** on the sensor (section 9).

### 4.6 TLS-PSK handshake

The sensor acts as the TLS **client** and the driver as the server, just like
`driver_5503.py` with `openssl s_server -nocert -psk 00…00`, but with OpenSSL
linked in and no processes or sockets:

- `SSL_CTX_new(TLS_server_method())`, `SSL_CTX_set_psk_server_callback`
  (returns the zero PSK and accepts any identity; the sensor sends
  `"Client_identity"`).
- Two memory BIOs (`BIO_s_mem`, with `BIO_set_mem_eof_return(-1)`) as the
  transport: what the sensor sends in `0xB0` packs is written into one; what
  OpenSSL produces is read from the other and sent in `0xB0` packs, without
  ACKs.
- Observed sequence: ClientHello (the sensor only offers `0x00ae`
  = PSK-AES128-CBC-SHA256) → ServerHello + ServerHelloDone →
  ClientKeyExchange, ChangeCipherSpec, Finished (three packs) →
  ChangeCipherSpec + Finished. The driver waits 10 ms after the last flight
  (goodix-fp-dump does so to avoid a USB timeout).
- Result: **TLS 1.2, PSK-AES128-CBC-SHA256**. The session stays in
  `self->tls` and is only used to decrypt images.

Note: the configuration and the other commands do **not** go through TLS;
only the image reply does.

### 4.7 Image capture

`mcu_get_image` is a normal command. The reply is a `0xB2` pack with 7758
bytes of data:

```
00 20 4a 1e 00 00 00 00 00 | 17 03 03 1e 40 …
└──── 9-byte prefix ─────┘   └── TLS 1.2 application-data record
```

In every capture seen so far the prefix is `[00][20 = cmd][length of what
follows the first 4 bytes, LE16][00 ×5]`. The driver checks that `17 03 03`
follows the prefix, decrypts the 7749 bytes of records with `SSL_read` and
gets **7684 bytes**; the last 4 are dropped (as in the script), leaving 7680
bytes = 5120 12-bit pixels.

Decoding (same as `tool.decode_image`), 6 bytes → 4 pixels:

```
p0 = ((b0 & 0xF) << 8) | b1        p1 = (b3 << 4) | (b0 >> 4)
p2 = ((b5 & 0xF) << 8) | b2        p3 = (b4 << 4) | (b5 >> 4)
```

**Geometry**: the pixels form **64 columns × 80 rows**. In `driver_5503.py`
the constants are named the other way round (`SENSOR_WIDTH = 80`,
`SENSOR_HEIGHT = 64`), but its `write_pgm` writes rows of 64. SIGFM was
initially given 80×64 (misaligned rows); this was fixed in `private.h`.

Typical raw frame values: no finger, mean ~1150-1170; finger, ~220-490 (up
to ~740 with partial contact).

### 4.8 Configuration and FDT payloads

`DEVICE_CONFIG` is **256 bytes** (not 272) and is sent as is. The template
"patched" it with 53x5 OTP values unless it was 272 bytes long, which in
practice corrupted its checksum; it is now sent unpatched.

FDT payloads (from `driver_5503.py`):
`[op][01][registers 8b 84 8c 88 as LE16][6 thresholds as LE16 with low byte 0x80]`.

| Use | op | Thresholds (high byte) |
|---|---|---|
| fdt_mode before the reference frame and for polling | `0d` | 96 91 92 85 8c 86 |
| fdt_mode after a capture | `0d` | b9 ae b9 af b5 aa |
| fdt_down (used by the Python script to wait for the finger) | `0c` | b9 ae b9 af b5 aa |
| final fdt_down ("idle") | `0c` | ba af ba b0 b6 ab |
| fdt_up #1 / #2 (unused) | `0e` | 95 89 99 8a 8d 8d / 9b 8e a2 90 9f a8 |

FDT replies carry `[02][00 or 01][mask 3f 00][6 readings LE16]`, one reading
per sensor zone.

---

## 5. Finger detection

### 5.1 Why the sensor's FDT events are not used

`driver_5503.py` waits for the finger with `mcu_switch_to_fdt_down(…, reply=True)`
and treats any `0x32` reply as "finger detected". On the real hardware,
**without a finger**, that reply always arrives ~34 ms after arming:

| Test (no finger) | Does the `0x32` arrive? |
|---|---|
| Python thresholds, armed twice | yes, after 34 ms |
| Thresholds = baseline reading + 0x10 | yes |
| Thresholds = baseline reading − 20 | yes |
| Thresholds 0xff | yes |
| Armed once | yes |

It is an unconditional reply ("armed, here are the readings"), not a
detection. The script only "works" if the finger is already on the sensor.
With a diagnostic probe (a 20 s passive phase after arming), **touching the
sensor produced no further message**. With the Python thresholds, `fdt_up`
without a finger never answered within 20 s (a likely cause of the hang in
`mcu_switch_to_fdt_up` reported in goodix-fp-dump issue 43). The other
goodix-fp-dump drivers follow the same pattern with thresholds copied from
Windows captures.

### 5.2 What actually changes with a finger

The `fdt_mode` readings were polled (4 times per second for 30 s, 122 cycles:
84 without a finger and 38 with one; the frame mean was used as ground
truth):

| | Zone 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| No finger, mean | 176.8 | 148.0 | 202.5 | 165.4 | 191.3 | 155.6 |
| No finger, standard deviation | 0.5 | 0.5 | 0.6 | 0.6 | 0.6 | 0.6 |
| Firm touch (example) | 49 | 54 | 95 | 5 | 36 | 45 |
| Fingertip (example) | 175 | 147 | 80 | 140 | 85 | 76 |

- A finger **lowers** the readings. Without a finger no zone strays more than
  2.6 from its mean; with real contact the most affected zone drops by **89
  or more**.
- A fingertip only covers zones 2-5: the rule must look at *any* zone.
- The headers (`02 01` / `02 00`) and the `3f` mask never change: there is no
  "touch" flag.
- The baseline shifts by a few points between runs, so it is measured at the
  start of every wait.

### 5.3 Algorithm (polling, `scan.c`)

Every ~100 ms (measured period: 9.9 Hz, ~1 % CPU) the driver sends `fdt_mode`
and reads the 6 zones.

- **Finger wait**: the first reading is the **no-finger baseline**. A finger
  is down when **any** zone is **≥ 20** below the baseline in **2
  consecutive readings** (those ~100-200 ms let the pressure settle before
  capturing).
- **Finger-up wait**: the finger is lifted when **every** zone is back within
  **≤ 10** of the baseline (the one from the finger wait of the same cycle,
  not a reading taken with the finger on) in **2 consecutive readings**. The
  gap between 20 and 10 prevents flapping.
- **Recovery**: if any zone **rises ≥ 20** above the baseline in 2 readings,
  the finger was already on the sensor when the baseline and the reference
  frame were taken (for example a quick re-touch right after lifting). Both
  are captured again and the wait continues. Without this, the wait hung
  forever.
- **Cancellation**: the action's `GCancellable` is checked before every
  reading (≤ 100 ms latency). There are no blocking USB reads, so system
  suspend completes immediately.
- **Wrap-up**: after the finger lifts (or after a successful verify) the tail
  of `driver_5503.py` is replayed: an "idle" `fdt_down`, consuming its
  immediate `0x32`, and `query_mcu_state(01 00 32)`.
- The transport drops any FDT event (`0x32`/`0x34`) that arrives where an ACK
  was expected.

### 5.4 Results

- No finger: 0 false positives (drops between −2 and +2 over hundreds of
  readings).
- Every touch was detected one reading after contact (~100 ms) and the
  capture followed ~37 ms later.
- Slow lift with the sensor half covered for 1-3 s: the covered zones stayed
  40-160 below the baseline, so there was never a premature finger-up or any
  flapping. Coverage per zone is almost binary, so the 20/10 hysteresis band
  was barely exercised.
- Quick repeated touches: the recovery fired 3 times; the contaminated
  reference frames (mean 304-343) were replaced by clean ones (1128-1130) and
  the next touch was detected.

---

## 6. Image and matching

### 6.1 Preprocessing

Before every wait a frame **without a finger** is captured (the reference,
the "clear" frame of `driver_5503.py`). The finger frame is subtracted from
the reference and normalised to 8 bits with the 3-97 % percentiles of the
interior (`goodix_device_image_to_8bit`). SIGFM applies CLAHE (4.0, 4×4) and
extracts SIFT features.

### 6.2 SIGFM and its score scale

Parameters: `distance_match 0.85`, `length_match 0.05`, `angle_match 0.05`,
`min_match 5`, SIFT (contrast 0.04, edge 18, sigma 2.0). The score counts
**pairs of match pairs** that are consistent in distance and rotation, so it
grows roughly as M⁴/8 for M consistent matches. The threshold
`GOODIX_SIGFM_BEST_MIN = 150` corresponds to about 6-7 matches. A template is
the 8 enroll samples; verify takes the best score.

### 6.3 Enroll

8 samples (`GOODIX_ENROLL_SAMPLES`); a sample with fewer than 20 SIFT
keypoints is rejected. The 53x5 template's "clipped fraction" filter (pixels
saturated at 4095) **never triggers on the 5503**, because its frames do not
saturate.

### 6.4 Measured accuracy

| Template | Enrolled finger | Other finger |
|---|---|---|
| Enroll with the finger always in the centre | 8/16 accepted | 0/5 (max 34) |
| Enroll moving over zones | 2/4 | 0/4 (max 1) |

Scores are all-or-nothing: matches range from 2387 to 483404; failures of
the enrolled finger from 0 to 16. **Lowering the threshold does not help**:
those failures score below what another finger reached (34).

The cause is **coverage**: the sensor sees a small part of the finger. The
centre of the pad is recognised; the tip and the sides fail if they are not
in the template. In practice (just as with the Windows driver) touching again
is enough. Measuring the contact coverage of the samples (pixels at least 300
darker than the reference), good samples cover 93-99 % of the sensor and
partial ones (tip, half empty) 43-83 %.

Proposed and deferred improvements (section 12): a coverage filter of
≥ ~85 % during enroll and raising the count to 16 samples.

---

## 7. Build, test and install

### 7.1 Build

Dependencies besides libfprint's own: OpenSSL ≥ 3.0 (`libssl-dev`) and
OpenCV 4 (`libopencv-dev`: core, features2d, flann, imgproc). Tested with
OpenSSL 3.0.2 and OpenCV 4.5.4.

libfprint requires **meson ≥ 0.62**; Ubuntu 22.04 / Mint 21 ship 0.61.2.
Meson 1.12 installed with pip in a virtual environment was used:

```bash
python3 -m venv ~/meson-venv && ~/meson-venv/bin/pip install meson ninja
~/meson-venv/bin/meson setup build -Ddrivers=goodix53x5
ninja -C build
```

The default driver list also needs `libudev-dev` (required by the SPI driver
`elanspi`); `-Ddrivers=goodix53x5` does not.

### 7.2 Testing without fprintd

To run the libfprint examples without root, give access to the device with
the development udev rule `tools/70-goodix5503.rules` (**remove it when
done**, section 11). fprintd must not be running (`systemctl is-active fprintd`).

The examples run from `build/` and keep their templates in
`build/test-storage.variant` (one per finger). They ask for the finger on
standard input (menu index, 6 = right index):

```bash
cd build
printf '6\nn\n' | ./examples/enroll
./examples/verify          # interactive: finger, then "Verify again? [Y/n]"
```

Practical notes:

- The examples turn on `G_MESSAGES_DEBUG=all` themselves and GLib writes
  debug output to **stdout**. To filter: `… 2>&1 | tee log | grep --line-buffered …`.
- The `Verify again?` prompt has no trailing newline, so a `grep` hides it.
  For repeated tests use `tools/verify-loop.sh`, which runs verify once per
  attempt and records which finger was used.
- After a `MATCH!` the driver does not wait for the finger to be lifted; lift
  it before starting another attempt.
- `GOODIX5503_DUMP_DIR` saves frames as PGM and `GOODIX5503_FDT_DEBUG=1` logs
  every polling reading (section 10).

### 7.3 Install

On this system fprintd loads libfprint from `/usr/local/lib/x86_64-linux-gnu/`
(check with `ldd /usr/libexec/fprintd | grep fprint`). The copy in
`/usr/lib/x86_64-linux-gnu/` (package `libfprint-2-2`) is ignored.

```bash
mkdir -p ~/libfprint-backup
cp -a /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0 ~/libfprint-backup/libfprint-2.so.2.0.0-$(date +%F)
sudo systemctl stop fprintd
sudo install -m 755 build/libfprint/libfprint-2.so.2.0.0 /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0
sudo ldconfig
ls -la /usr/local/lib/x86_64-linux-gnu/libfprint-2.so*
cmp build/libfprint/libfprint-2.so.2.0.0 /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0 && echo OK
```

- Keep backups **outside** that directory: `ldconfig` may point
  `libfprint-2.so.2` at a `.bak` file sitting next to it.
- After installing, enroll the finger with `fprintd-enroll`; the examples'
  templates are not shared with fprintd.
- To roll back: `sudo install` the backup + `sudo ldconfig`.

---

## 8. fprintd, PAM and the login screen

```bash
fprintd-enroll -f right-index-finger
fprintd-verify
sudo apt install libpam-fprintd
sudo pam-auth-update            # tick "Fingerprint authentication"
```

- Mint's profile writes `pam_fprintd.so max-tries=1 timeout=10` into
  `/etc/pam.d/common-auth` (1 attempt, 10 s). On this machine it was raised
  to `max-tries=3 timeout=30`. Once they are used up, the password is asked
  for; in a terminal, Ctrl+C skips straight to the password.
- fprintd's prompt is "Place your … finger on <device name>". The login
  screen (LightDM + slick-greeter) truncated it with the template's name
  ("Goodix HTK32 Fingerprint Sensor"), hence `full_name` is now
  "Goodix 5503".
- slick-greeter shows the password field and the fingerprint prompt at the
  same time; while `pam_fprintd` is waiting, the password is only accepted
  after the fingerprint gives up.
- **GNOME keyring**: a fingerprint login has no password to unlock it, so it
  is asked for separately ("login keyring did not get unlocked"). This is the
  normal behaviour on Linux. Options: keep it (asked once per session; the
  choice made here), remove its password with Seahorse (stored unencrypted on
  disk), or use the password only on the login screen. Storing the user
  password to "fill it in" after the fingerprint was rejected: whoever reads
  it gets root access. A TPM-sealed unlock (the machine has a TPM 2.0) adds
  little while the disk is not encrypted.
- To remove the fingerprint from the login screen only, replace
  `@include common-auth` in `/etc/pam.d/lightdm` with an explicit copy of the
  password lines of `common-auth`. **Do not** use the "skip the first line"
  trick: if the fingerprint were later disabled, it would skip the password
  and lock everyone out.

---

## 9. Dual boot with Windows (PSK)

The Windows driver provisions **its own PSK** on the sensor. At the start of
this work the sensor had the hash `2c26e305…` (neither the zero PSK nor
`driver_5503.py`'s) even though the Python script had been run before. The
driver's first open wrote the zero PSK; the hash then became `81b8ff49…`
(`PMK_HASH`). The write was made optional so as not to overwrite Windows' PSK
on every open.

**Confirmed behaviour:**

- Windows writes a **new** PSK whenever it finds one that is not its own.
  After the first write of the zero PSK, one Windows boot left the hash
  `5104d34c…`, different from the original `2c26e305…`. **Windows Hello kept
  recognising the finger** without re-enrolling.
- Without write permission, Linux fails cleanly on return: `journalctl -u
  fprintd` shows `PSK mismatch, write skipped` and the TLS handshake ends with
  `bad record mac`. The fingerprint becomes unavailable, but fprintd's
  templates are not lost (they do not depend on the PSK).

**Recommended setup for dual boot:** let fprintd rewrite the PSK through a
systemd drop-in ([`tools/goodix5503-psk.conf`](tools/goodix5503-psk.conf)):

```bash
sudo mkdir -p /etc/systemd/system/fprintd.service.d
sudo cp docs/goodix5503/tools/goodix5503-psk.conf /etc/systemd/system/fprintd.service.d/
sudo systemctl daemon-reload && sudo systemctl restart fprintd
systemctl show fprintd -p Environment     # must show GOODIX5503_ALLOW_PSK_WRITE=1
```

The first fingerprint use after coming back from Windows then logs
`PSK mismatch and GOODIX5503_ALLOW_PSK_WRITE=1: writing PSK white box` and
works normally; Windows does the same on its side. Tested on this machine.
Every OS switch costs one write to the sensor's flash, which is acceptable for
normal use.

To undo it:
`sudo rm /etc/systemd/system/fprintd.service.d/goodix5503-psk.conf && sudo systemctl daemon-reload && sudo systemctl restart fprintd`.

Without the drop-in, the PSK can be rewritten once by hand with the examples:
`printf '6\n' | GOODIX5503_ALLOW_PSK_WRITE=1 ./examples/verify` from
`build/`, then Ctrl+C once `Waiting for finger down` appears.

---

## 10. Environment variables

| Variable | Effect |
|---|---|
| `GOODIX5503_ALLOW_PSK_WRITE=1` | Allows writing the zero PSK when the sensor's does not match (persistent) |
| `GOODIX5503_DUMP_DIR=<dir>` | Saves every frame as `clear-N.pgm` / `finger-N.pgm` (`tool.write_pgm` format); numbering restarts at 0 in every process |
| `GOODIX5503_FDT_DEBUG=1` | Logs every polling reading (`FDT-POLL …`: zones, drops, counter) |

Everything else is logged at debug level (`G_MESSAGES_DEBUG=all`): every USB
transfer in hex (`USB TX` / `USB RX`), the TLS handshake step by step and the
polling state changes. A normal open emits no warnings.

---

## 11. Security

- **Public PSK**: the PSK is the all-zero one used by goodix-fp-dump. Anyone
  who can talk to the sensor over USB can establish the TLS session and
  decrypt images. With fprintd only root can access the device; the
  development udev rule (`MODE="0666"`) opens it to every local process and
  must be removed when done.
- **Diagnostic PGMs**: they are fingerprint images (biometric data). None are
  included in this repository and they must not be published.
- **Templates**: fprintd stores the SIGFM features in `/var/lib/fprint/`
  (root only).

---

## 12. Limitations and future work

**Before proposing the driver to libfprint:**

- `goodix53x5_id_table` still lists `0x5335`, `0x5385` and `0x5395`, but the
  driver now only speaks the 5503 protocol: those sensors would stop
  working. They must be removed, or the 5503 split into its own driver.
- Inherited code unused on the 5503: GTLS (`crypto.c`), OTP/FDT math
  (`calibration.c`), 53x5 commands (`fdt_manual`, `request_image`,
  `ec_control`, `mcu_send`, …) and part of the transport's suspend logic
  meant for blocking reads.
- The driver is named `goodix53x5`; renaming it would change the path of the
  templates in fprintd (`/var/lib/fprint/<user>/<driver>/…`).

**Features:**

- Enroll coverage: a contact coverage filter (reject samples below ~85 %)
  and 16 samples instead of 8. Deferred on purpose: in practice touching
  again is enough.
- `GOODIX5503_DUMP_DIR` overwrites files across processes (numbering
  restarts); the file names should include the time.
- The real semantics of `fdt_down` / `fdt_up` as a sensor interrupt are still
  unknown. A USB capture of Windows Hello (USBPcap; goodix-fp-dump ships a
  Wireshark dissector) would show how Windows computes the thresholds and
  would allow waiting for the finger without polling (lower power).
- The OTP is not interpreted and no per-sensor calibration is used.
- Only one 27c6:5503 unit has been tested.

---

## 13. Project history

The findings in order, to avoid retracing paths that were already ruled out.

1. **Starting point.** The goodix53x5 template directory with PID 0x5503
   added. The interface was claimed fine, but the first ping timed out.
2. **Wrong protocol.** Comparing byte by byte with `goodix.py`: the 5503
   expects `0xA0` message packs, 64-byte writes and a nop without checksum
   and without a mandatory ACK; the template used the wrapless protocol (CDC
   interface 1). The transport was rewritten; the open got as far as the PSK.
3. **PSK and Windows.** The sensor had an unknown PSK; the first open
   overwrote it with the zero PSK. The write was made optional.
4. **TLS.** The sensor is a TLS-PSK client; the server was implemented with
   OpenSSL memory BIOs. The handshake flag is `0xB0`, not `0xB2`.
5. **Configuration and first image.** `DEVICE_CONFIG` is 256 bytes (the 53x5
   patching would have corrupted it). The image arrives in a `0xB2` pack
   (9-byte prefix + TLS) and decrypts to 7684 bytes. The reference images of
   the Python project turned out to all have the finger on the sensor.
6. **Capture in scan.c and geometry.** The template's sub-SSM pattern was
   reused. The image is 64×80, not 80×64.
7. **Finger detection.** The `0x32` after `fdt_down` is unconditional (the
   experiments in 5.1). A diagnostic probe with the user touching the sensor
   showed that a finger lowers the zone readings; the event-based wait was
   replaced by 10 Hz polling of `fdt_mode` with measured thresholds.
8. **Enroll and verify.** First complete 8/8 enroll. Verify: no false
   positives; false negatives due to sensor coverage, accepted.
9. **Installation.** Debug warnings cleaned up; fix for the hang on quick
   touches (reference frame taken with the finger on); PAM; short device
   name for the login screen; decision about the keyring.
10. **Dual boot.** After a Windows boot the sensor had a new PSK and Linux
    failed as intended (without writing anything). Windows Hello had kept
    working, so automatic rewriting was enabled in fprintd with a systemd
    drop-in; since then the fingerprint works in both systems. Unlocking
    after a suspend was checked as well.

---

## 14. Analysis tools

In `docs/goodix5503/tools/`:

| Tool | Use |
|---|---|
| `fdt_poll_analysis.py LOG` | Summary of every wait in a log recorded with `GOODIX5503_FDT_DEBUG=1`: readings before the touch, counter resets during the lift, recoveries |
| `verify_analysis.py LOG` | Table of a `verify-loop.sh` log: detection, score per sample, result, matches per finger type |
| `verify-loop.sh [FINGER] [LOG]` | Repeated, labelled verify, run from `build/` |
| `coverage.py DIR [THRESHOLD]` | Contact coverage of `clear-N`/`finger-N` pairs from `GOODIX5503_DUMP_DIR` |
| `pgm_montage.py OUT.png A.pgm …` | Frames side by side in one PNG (needs Pillow) |
| `70-goodix5503.rules` | Development udev rule (testing only) |
| `goodix5503-psk.conf` | systemd drop-in so fprintd rewrites the PSK after Windows (section 9) |

Example detection test:

```bash
cd build
printf '3\nn\n' | GOODIX5503_FDT_DEBUG=1 ./examples/enroll 2>&1 | tee ~/poll.log |
  grep --line-buffered -oE "Waiting for finger (down|up)|Finger (down|up) detected.*|retaking.*|Enroll stage.*"
../docs/goodix5503/tools/fdt_poll_analysis.py ~/poll.log
```

---

## 15. References

- goodix-fp-dump (protocol, `driver_5503.py`, MIT):
  <https://github.com/goodix-fp-linux-dev/goodix-fp-dump> (commit `cc43bb3`)
- goodix53x5-libfprint (template, LGPL-2.1):
  <https://github.com/AndyHazz/goodix53x5-libfprint> (commit `309d4c6`)
- SIGFM (LGPL-2.1+): included in the template, `libfprint/sigfm/`
- libfprint: <https://gitlab.freedesktop.org/libfprint/libfprint>
  (base: `6f9479c3`)
