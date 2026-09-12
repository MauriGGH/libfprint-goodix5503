# libfprint con soporte para Goodix 27c6:5503

> Fork de [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) que
> añade un driver para el lector de huellas **Goodix `27c6:5503`** (Lenovo
> IdeaPad 3 15ITL6 / 82H8), hasta ahora sin soporte en Linux.
>
> *Fork of libfprint adding a driver for the Goodix 27c6:5503 fingerprint
> sensor. Full documentation (in Spanish):
> [docs/goodix5503/README.md](docs/goodix5503/README.md).*

Con este driver el lector funciona con **fprintd**: registro de huellas,
verificación, `sudo` e inicio de sesión mediante PAM, en un equipo con
arranque dual con Windows.

**Documentación completa del proceso y los hallazgos:
[docs/goodix5503/README.md](docs/goodix5503/README.md)**
(protocolo, mediciones, decisiones, instalación, limitaciones e historia del
proyecto).

## Estado

| Función | Estado |
|---|---|
| Apertura, handshake TLS-PSK y configuración del sensor | Funciona |
| Captura y descifrado de imágenes (64×80, 12 bits) | Funciona |
| Detección de dedo puesto / retirado | Funciona (sondeo de zonas) |
| Enroll, verify e identify (matching SIGFM) | Funciona |
| fprintd + PAM (`sudo`, inicio de sesión) | Funciona |
| Arranque dual con Windows | Funciona, reescribiendo el PSK al volver a Linux |
| Bloqueo de pantalla, suspender/reanudar | Sin probar |

Precisión medida: ningún otro dedo aceptado (0 de 9 intentos). El centro de la
yema se reconoce de forma fiable; la punta y los costados pueden requerir
repetir el toque, porque el sensor solo ve una parte del dedo.

## Qué cambia respecto a libfprint

- `libfprint/drivers/goodix53x5/`: el driver. Parte de
  [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)
  (chips 5335/5385/5395), pero el 5503 usa otro protocolo, así que el
  transporte, la sesión, el cifrado y la captura están reescritos según
  `driver_5503.py` de
  [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump).
- `libfprint/sigfm/`: matching de huellas basado en SIFT (OpenCV), de la misma
  plantilla.
- `meson.build`, `libfprint/meson.build`: registro del driver, OpenSSL y OpenCV.
- `docs/goodix5503/`: documentación y herramientas de análisis.

## Hallazgos principales

- **Protocolo**: cada transferencia va en un "message pack" (`0xA0` comandos,
  `0xB0` handshake TLS, `0xB2` imágenes), con escrituras de 64 bytes.
- **Cifrado**: el sensor abre una sesión TLS 1.2 PSK
  (`PSK-AES128-CBC-SHA256`) como cliente; el driver es el servidor, con OpenSSL
  sobre BIOs de memoria. Solo las imágenes viajan cifradas.
- **Detección de dedo**: los eventos FDT del sensor no sirven (responde al
  armado siempre, haya dedo o no). El driver sondea a 10 Hz las lecturas de
  las 6 zonas del sensor, con umbrales medidos: el dedo baja las lecturas 89
  puntos o más, frente a un ruido de ±2.6.
- **Arranque dual**: Windows escribe su propio PSK en el sensor cada vez que
  encuentra otro. Windows Hello sigue funcionando, y en Linux fprintd puede
  reescribir el suyo automáticamente (`GOODIX5503_ALLOW_PSK_WRITE=1`).

## Instalación rápida

Resumen; los detalles, advertencias y cómo volver atrás están en la
[documentación](docs/goodix5503/README.md#7-compilar-probar-e-instalar).

```bash
# meson >= 0.62 (el de Ubuntu 22.04 / Mint 21 es más antiguo)
python3 -m venv ~/meson-venv && ~/meson-venv/bin/pip install meson ninja
~/meson-venv/bin/meson setup build -Ddrivers=goodix53x5
ninja -C build

# Instalar donde lo cargue fprintd (comprobar con: ldd /usr/libexec/fprintd)
sudo install -m 755 build/libfprint/libfprint-2.so.2.0.0 /usr/local/lib/x86_64-linux-gnu/
sudo ldconfig

fprintd-enroll -f right-index-finger
sudo apt install libpam-fprintd && sudo pam-auth-update
```

Con arranque dual, añadir además el drop-in de systemd
[`docs/goodix5503/tools/goodix5503-psk.conf`](docs/goodix5503/tools/goodix5503-psk.conf)
(ver la [sección 9](docs/goodix5503/README.md#9-arranque-dual-con-windows-psk)).

## Créditos y licencia

- Protocolo del 5503: [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) (MIT).
- Driver base y SIGFM: [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint) (LGPL-2.1).
- libfprint: LGPL-2.1, ver el README original a continuación.

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
