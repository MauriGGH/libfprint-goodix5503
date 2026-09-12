# libfprint with Goodix 27c6:5503 support

> Fork of [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)
> that adds a driver for the **Goodix `27c6:5503`** fingerprint reader
> (Lenovo IdeaPad 3 15ITL6 / 82H8), which had no Linux support.

With this driver the reader works with **fprintd**: enrollment, verification,
`sudo` and login through PAM, on a machine that dual-boots Windows.

**Full documentation of the process and findings:
[docs/goodix5503/README.md](docs/goodix5503/README.md)**
(protocol, measurements, decisions, installation, limitations and project
history).

## Status

| Feature | Status |
|---|---|
| Sensor open, TLS-PSK handshake and configuration | Works |
| Image capture and decryption (64×80, 12-bit) | Works |
| Finger down / finger up detection | Works (zone polling) |
| Enroll, verify and identify (SIGFM matching) | Works |
| fprintd + PAM (`sudo`, login) | Works |
| Dual boot with Windows | Works, rewriting the PSK when coming back to Linux |
| Lock screen, suspend/resume | Works (unlocking after a suspend tested) |

Measured accuracy: no other finger accepted (0 out of 9 attempts). The centre
of the pad is recognised reliably; the tip and the sides may need a second
touch, because the sensor only sees part of the finger.

## What changes compared to libfprint

- `libfprint/drivers/goodix53x5/`: the driver. It starts from
  [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)
  (5335/5385/5395 chips), but the 5503 speaks a different protocol, so the
  transport, session, encryption and capture are rewritten after
  `driver_5503.py` from
  [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump).
- `libfprint/sigfm/`: SIFT-based fingerprint matching (OpenCV), from the same
  template.
- `meson.build`, `libfprint/meson.build`: driver registration, OpenSSL and
  OpenCV.
- `docs/goodix5503/`: documentation and analysis tools.

## Main findings

- **Protocol**: every transfer is a "message pack" (`0xA0` commands, `0xB0`
  TLS handshake, `0xB2` images), written in 64-byte chunks.
- **Encryption**: the sensor opens a TLS 1.2 PSK session
  (`PSK-AES128-CBC-SHA256`) as the client; the driver is the server, using
  OpenSSL over memory BIOs. Only images travel encrypted.
- **Finger detection**: the sensor's FDT events are unusable (it answers the
  arming every time, finger or not). The driver polls the readings of the
  sensor's 6 zones at 10 Hz with measured thresholds: a finger lowers them by
  89 points or more, against ±2.6 of noise.
- **Dual boot**: Windows writes its own PSK to the sensor whenever it finds
  another one. Windows Hello keeps working, and on Linux fprintd can write its
  own back automatically (`GOODIX5503_ALLOW_PSK_WRITE=1`).

## Quick install

A summary; details, caveats and how to roll back are in the
[documentation](docs/goodix5503/README.md#7-build-test-and-install).

```bash
# meson >= 0.62 (Ubuntu 22.04 / Mint 21 ship an older one)
python3 -m venv ~/meson-venv && ~/meson-venv/bin/pip install meson ninja
~/meson-venv/bin/meson setup build -Ddrivers=goodix53x5
ninja -C build

# Install where fprintd loads it from (check with: ldd /usr/libexec/fprintd)
sudo install -m 755 build/libfprint/libfprint-2.so.2.0.0 /usr/local/lib/x86_64-linux-gnu/
sudo ldconfig

fprintd-enroll -f right-index-finger
sudo apt install libpam-fprintd && sudo pam-auth-update
```

On dual-boot machines also add the systemd drop-in
[`docs/goodix5503/tools/goodix5503-psk.conf`](docs/goodix5503/tools/goodix5503-psk.conf)
(see [section 9](docs/goodix5503/README.md#9-dual-boot-with-windows-psk)).

## Credits and license

- 5503 protocol: [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) (MIT).
- Base driver and SIGFM: [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint) (LGPL-2.1).
- libfprint: LGPL-2.1, see the original README below.

---

<div align="center">

# LibFPrint

*LibFPrint is part of the **[FPrint][Website]** project.*

<br/>

[![Button Website]][Website]
[![Button Documentation]][Documentation]

[![Button Supported]][Supported]
[![Button Unsupported]][Unsupported]

[![Button Contribute]][Contribute]
[![Button Contributors]][Contributors]

</div>

## History

**LibFPrint** was originally developed as part of an
academic project at the **[University Of Manchester]**.

It aimed to hide the differences between consumer
fingerprint scanners and provide a single uniform
API to application developers.

## Goal

The ultimate goal of the **FPrint** project is to make
fingerprint scanners widely and easily usable under
common Linux environments.

## License

`Section 6` of the license states that for compiled works that use
this library, such works must include **LibFPrint** copyright notices
alongside the copyright notices for the other parts of the work.

**LibFPrint** includes code from **NIST's** **[NBIS]** software distribution.

We include **Bozorth3** from the **[US Export Controlled]**
distribution, which we have determined to be fine
being shipped in an open source project.

## Get in *touch*

 - [IRC] - `#fprint` @ `irc.oftc.net`
 - [Matrix] - `#fprint:matrix.org` bridged to the IRC channel
 - [MailingList] - low traffic, not much used these days

<br/>

<div align="right">

[![Badge License]][License]

</div>


<!----------------------------------------------------------------------------->

[Documentation]: https://fprint.freedesktop.org/libfprint-dev/
[Contributors]: https://gitlab.freedesktop.org/libfprint/libfprint/-/graphs/master
[Unsupported]: https://gitlab.freedesktop.org/libfprint/wiki/-/wikis/Unsupported-Devices
[Supported]: https://fprint.freedesktop.org/supported-devices.html
[Website]: https://fprint.freedesktop.org/
[MailingList]: https://lists.freedesktop.org/mailman/listinfo/fprint
[IRC]: ircs://irc.oftc.net:6697/#fprint
[Matrix]: https://matrix.to/#/#fprint:matrix.org

[Contribute]: ./HACKING.md
[License]: ./COPYING

[University Of Manchester]: https://www.manchester.ac.uk/
[US Export Controlled]: https://fprint.freedesktop.org/us-export-control.html
[NBIS]: http://fingerprint.nist.gov/NBIS/index.html


<!---------------------------------[ Badges ]---------------------------------->

[Badge License]: https://img.shields.io/badge/License-LGPL2.1-015d93.svg?style=for-the-badge&labelColor=blue


<!---------------------------------[ Buttons ]--------------------------------->

[Button Documentation]: https://img.shields.io/badge/Documentation-04ACE6?style=for-the-badge&logoColor=white&logo=BookStack
[Button Contributors]: https://img.shields.io/badge/Contributors-FF4F8B?style=for-the-badge&logoColor=white&logo=ActiGraph
[Button Unsupported]: https://img.shields.io/badge/Unsupported_Devices-EF2D5E?style=for-the-badge&logoColor=white&logo=AdBlock
[Button Contribute]: https://img.shields.io/badge/Contribute-66459B?style=for-the-badge&logoColor=white&logo=Git
[Button Supported]: https://img.shields.io/badge/Supported_Devices-428813?style=for-the-badge&logoColor=white&logo=AdGuard
[Button Website]: https://img.shields.io/badge/Homepage-3B80AE?style=for-the-badge&logoColor=white&logo=freedesktopDotOrg
