# Driver libfprint para Goodix 27c6:5503

Documentación del trabajo para hacer funcionar el lector de huellas Goodix
`27c6:5503` (Lenovo IdeaPad 3 15ITL6 / 82H8) con libfprint y fprintd en Linux,
incluido el inicio de sesión y `sudo` mediante PAM.

No existía ningún driver para este PID. Se construyó a partir de dos fuentes:
el script Python de ingeniería inversa `driver_5503.py` del proyecto
[goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) (que
define el protocolo) y el driver libfprint
[AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)
(commit `309d4c6`) para los chips 5335/5385/5395, que aportó la arquitectura
(máquinas de estados, integración con libfprint y matching SIGFM). Resultó que
el protocolo de esa plantilla **no** es el del 5503, así que casi todo el
transporte, la sesión y la captura se reescribieron.

Este documento explica qué hace el driver, cómo se descubrió cada cosa, qué
datos respaldan cada decisión, cómo compilarlo, probarlo e instalarlo, y qué
queda pendiente.

---

## Índice

1. [Estado actual](#1-estado-actual)
2. [Hardware](#2-hardware)
3. [Organización del código](#3-organización-del-código)
4. [Protocolo USB del 5503](#4-protocolo-usb-del-5503)
5. [Detección de dedo](#5-detección-de-dedo)
6. [Imagen y matching](#6-imagen-y-matching)
7. [Compilar, probar e instalar](#7-compilar-probar-e-instalar)
8. [fprintd, PAM y el inicio de sesión](#8-fprintd-pam-y-el-inicio-de-sesión)
9. [Arranque dual con Windows (PSK)](#9-arranque-dual-con-windows-psk)
10. [Variables de entorno](#10-variables-de-entorno)
11. [Seguridad](#11-seguridad)
12. [Limitaciones y trabajo pendiente](#12-limitaciones-y-trabajo-pendiente)
13. [Historia del proyecto](#13-historia-del-proyecto)
14. [Herramientas de análisis](#14-herramientas-de-análisis)
15. [Referencias](#15-referencias)

---

## 1. Estado actual

| Función | Estado |
|---|---|
| Apertura del dispositivo (USB, PSK, TLS, configuración) | Funciona |
| Handshake TLS-PSK con el sensor | Funciona (TLS 1.2, `PSK-AES128-CBC-SHA256`) |
| Captura y descifrado de imágenes (64×80, 12 bits) | Funciona |
| Detección de dedo puesto / retirado | Funciona, por sondeo de zonas (sección 5) |
| Enroll (8 muestras) | Funciona |
| Verify / identify (SIGFM) | Funciona; ver precisión en 6.4 |
| fprintd + PAM (`sudo`, inicio de sesión) | Funciona |
| Arranque dual con Windows | Funciona, reescribiendo el PSK automáticamente (sección 9) |
| Bloqueo de pantalla, suspender/reanudar | Sin probar |

Precisión medida (sección 6.4): **0 de 9** intentos con otro dedo aceptados.
Con el dedo registrado, el centro de la yema se reconoce de forma fiable; la
punta y los costados fallan si no están en la plantilla (el sensor solo ve una
parte del dedo).

---

## 2. Hardware

| | |
|---|---|
| Equipo | Lenovo IdeaPad 3 15ITL6 (82H8), i7-1165G7 |
| USB | `27c6:5503` "Goodix FingerPrint Device", USB 2.0 alta velocidad |
| Interfaz | 0, clase 255 (vendor specific) |
| Endpoints | `0x01` bulk OUT, `0x82` bulk IN, `wMaxPacketSize` 512 |
| Firmware | `GF3208_RTSEC_APP_10062` (IAP `MILAN_RTSEC_IAP_10027` según goodix-fp-dump) |
| Chip ID | `0x00220fa6` (bytes `0f a6 00 22` del registro 0) |
| OTP | 64 bytes (no se interpreta; ver 12) |
| Imagen | 5120 píxeles de 12 bits = 7680 bytes, **64 columnas × 80 filas** |

El equipo tiene arranque dual con Windows, donde el driver oficial de Goodix
(3.1.586.580) funciona. Esto importa por el PSK (sección 9).

---

## 3. Organización del código

El driver conserva el nombre `goodix53x5` de la plantilla (la carpeta, el
`FP_COMPONENT` y el id de driver en meson) y se identifica ante el usuario como
**"Goodix 5503"** (`full_name`). Es un `FpDevice` (no un `FpImageDevice`): hace
el matching dentro del driver con SIGFM y guarda plantillas "raw" en fprintd.

### 3.1 Archivos (`libfprint/drivers/goodix53x5/`)

| Archivo | Contenido |
|---|---|
| `goodix53x5.c` | Clase GObject, tabla de IDs USB, `open`/`close`/`enroll`/`verify`/`identify` |
| `goodix53x5-private.h` | Estado del dispositivo, geometría del sensor, constantes PSK |
| `goodix53x5-proto.c/h` | Formato de "message pack" y de mensaje de protocolo, reensamblado de lecturas |
| `goodix53x5-transport.c/h` | Transferencias USB, sub-SSM de comando (enviar → ACK → datos), drenaje, volcado hex |
| `goodix53x5-commands.c/h` | Comandos con nombre (nop, firmware, reset, PSK, TLS, config, FDT, imagen…) |
| `goodix53x5-session.c/h` | SSM de apertura, escritura opcional del PSK, handshake TLS, reinicialización tras suspensión |
| `goodix53x5-tls.c/h` | Servidor TLS-PSK con OpenSSL sobre BIOs de memoria |
| `goodix53x5-scan.c/h` | Referencia sin dedo, espera de dedo (sondeo), captura, espera de retirada, desactivación |
| `goodix53x5-image.c/h` | Decodificación 12 bits, PGM de diagnóstico, preprocesado a 8 bits |
| `goodix53x5-enroll.c/h` | SSM de enroll y construcción de la plantilla |
| `goodix53x5-auth.c/h` | SSM de verify/identify y decisión de coincidencia |
| `goodix53x5-match.c/h` | Envoltorio C de SIGFM (extracción, serialización, puntuación) |
| `goodix53x5-calibration.c/h` | `DEVICE_CONFIG` del 5503; el resto es cálculo de OTP/FDT de la 53x5 (no se usa) |
| `goodix53x5-crypto.c/h` | Restos de "GTLS" de la 53x5 (no se usan en el 5503) |

`libfprint/sigfm/` contiene SIGFM (matching basado en SIFT con OpenCV), tomado
de la plantilla. Cambios de build: `libfprint/meson.build` (fuentes del driver,
OpenCV, `libsigfm`) y `meson.build` (entrada del driver con el helper `openssl`).

### 3.2 Máquinas de estados

Todo es asíncrono sobre el bucle de GLib: cada paso es un estado de un `FpiSsm`
y las esperas usan transferencias USB o temporizadores
(`fpi_ssm_jump_to_state_delayed`), nunca bucles bloqueantes.

- **Apertura** (`session.c`): `USB_RESET` (set_configuration) → `CLAIM_INTERFACE`
  → `DRAIN` → `PING` → `READ_FW_VERSION` → `RESET` → `READ_CHIP_ID` →
  `READ_OTP` → `PARSE_OTP` → `READ_PSK_HASH` → `WRITE_PSK` →
  `VERIFY_PSK_WRITE` → `CHECK_PSK_WRITE` → `TLS_REQUEST` → `TLS_RECV` ⇄
  `TLS_FEED` ⇄ `TLS_SENT` → `TLS_COMPLETE` → `UPLOAD_CONFIG` →
  `SET_DRV_STATE_1` → `SET_DRV_STATE_2` → `POV_IMAGE` → `POV_IMAGE_DONE`.
- **Enroll** (`enroll.c`): `REINIT` → `CAPTURE_REF` → `WAIT_FINGER` →
  `CAPTURE` → `PROCESS` (SIGFM) → `WAIT_FINGER_UP` → `NEXT` (350 ms) ×8.
- **Verify/identify** (`auth.c`): `REINIT` → `CAPTURE_REF` → `WAIT_FINGER` →
  `CAPTURE` → `MATCH` → `FINISH` (espera de retirada si no coincide,
  desactivación si coincide).
- **Sub-SSMs de captura** (`scan.c`): referencia sin dedo, espera de dedo,
  captura, espera de retirada, desactivación (sección 5).
- **Sub-SSM de comando** (`transport.c`): `SEND` → `RECV_ACK` →
  `VALIDATE_ACK` → `RECV_DATA`.

---

## 4. Protocolo USB del 5503

La fuente de verdad es `driver_5503.py` + `goodix.py` + `protocol.py` de
goodix-fp-dump. La plantilla 53x5 implementa otro protocolo ("wrapless", el de
`driver_53x5.py`: interfaz CDC 1, trozos de continuación `cmd|1`, GTLS por
mensajes MCU `0xFF01…`), que el 5503 descarta en silencio. Ese fue el primer
bloqueo (el ping no recibía respuesta).

### 4.1 Message pack

Cada transferencia va envuelta en:

```
[flags 1][longitud 2 LE][checksum 1][datos…]
checksum = (flags + longitud_lo + longitud_hi) & 0xFF
```

| flags | Contenido |
|---|---|
| `0xA0` | Mensaje de protocolo (comandos, respuestas, ACKs) |
| `0xB0` | Registros TLS del handshake |
| `0xB2` | Datos de imagen: prefijo de 9 bytes + registros TLS de datos |

Escritura: el pack se rellena con ceros hasta múltiplo de 64 y se envía en
transferencias de 64 bytes (como `protocol.py`). Lectura: una transferencia de
hasta 64 KiB; si el pack es mayor, se sigue leyendo y se concatena.

### 4.2 Mensaje de protocolo (dentro de un pack `0xA0`)

```
[cmd 1][tamaño 2 LE = payload+1][payload…][checksum 1]
cmd      = categoría << 4 | comando << 1
checksum = (0xAA - suma de todos los bytes anteriores) & 0xFF, o 0x88 si no se usa
```

Cada comando recibe primero un **ACK** (`cmd 0xB0`, payload
`[cmd reconocido][flags]`, bit 0 = válido) y, si corresponde, después un
mensaje de respuesta con el mismo `cmd`.

### 4.3 Comandos usados

| cmd | cat/cmd | Nombre (goodix.py) | Payload | Respuesta |
|---|---|---|---|---|
| `0x00` | 0/0 | nop | `00 00 00 00`, checksum `0x88` | ACK opcional (normalmente no llega) |
| `0xA8` | A/4 | firmware_version | `00 00` | cadena de firmware |
| `0xA2` | A/1 | reset (sensor) | `05 14` (reset_sensor, 20 ms) | `[01][número LE16]` |
| `0x82` | 8/1 | read_sensor_register | `00 00 00 04` | 4 bytes (chip ID) |
| `0xA6` | A/3 | read_otp | `00 00` | 64 bytes |
| `0xE4` | E/2 | preset_psk_read | `07 00 02 bb 00 00 00 00` | `[estado][flags LE32][len LE32][hash]` |
| `0xE0` | E/0 | preset_psk_write | flags `0xbb010003` + len + white box (96 B) | `[estado]` (0 = ok) |
| `0xD0` | D/0 | request_tls_connection | `00 00` | ACK; luego un pack `0xB0` con el ClientHello |
| `0x90` | 9/0 | upload_config_mcu | `DEVICE_CONFIG` (256 B) | `[01]` |
| `0xC4` | C/2 | set_drv_state | `01 00` | solo ACK (se envía dos veces, como Windows) |
| `0xD2` | D/1 | mcu_get_pov_image | `00 00` | `[estado]` (`0xff`) |
| `0x36` | 3/3 | mcu_switch_to_fdt_mode | 22 B (4.8) | `[02 01][máscara 3f 00][6 zonas LE16]` |
| `0x20` | 2/0 | mcu_get_image | `01 00 8b 00 84 00 8c 00 88 00` | pack `0xB2` (4.7) |
| `0x32` | 3/1 | mcu_switch_to_fdt_down | 22 B | ACK + un `0x32` incondicional a los ~34 ms (5.1) |
| `0xAE` | A/7 | query_mcu_state | `01 00 32` | 2 bytes |

Otros comandos de goodix.py (`0x34` fdt_up, `0xD6` pov_image_check,
`0x70` idle, …) existen pero el driver actual no los usa.

### 4.4 Apertura

1. `set_configuration(1)`, reclamar la interfaz 0 (desligando el driver del
   kernel si lo hubiera).
2. **Drenaje**: leer y descartar lo que haya pendiente en `0x82` hasta un
   timeout de 100 ms (equivale a `empty_buffer()` de goodix.py).
3. nop, versión de firmware, reset del sensor, chip ID, OTP.
4. **PSK** (4.5).
5. **Handshake TLS** (4.6).
6. `upload_config_mcu(DEVICE_CONFIG)`, `set_drv_state` ×2, `mcu_get_pov_image`.

### 4.5 PSK

El sensor guarda un PSK en su flash y cifra las imágenes con una sesión TLS
basada en él. `driver_5503.py` usa el PSK de **32 bytes a cero**; su hash
(`PMK_HASH`) es `81b8ff49…5ee50361`. El driver lee el hash con
`preset_psk_read(0xbb020007)` y lo compara con `PMK_HASH` y con `sha256(PSK)`.

Si no coincide, **por defecto no escribe nada**: registra
`PSK mismatch, write skipped - set GOODIX5503_ALLOW_PSK_WRITE=1 to write it`,
sigue, y el handshake TLS falla más adelante con un mensaje que lo indica.
Solo con `GOODIX5503_ALLOW_PSK_WRITE=1` escribe el "white box" del PSK cero
(`preset_psk_write(0xbb010003, PSK_WHITE_BOX)`) y verifica releyendo el hash.
La escritura es **persistente** en el sensor (sección 9).

### 4.6 Handshake TLS-PSK

El sensor actúa como **cliente** TLS y el driver como servidor, igual que
`driver_5503.py` con `openssl s_server -nocert -psk 00…00`, pero con OpenSSL
enlazado y sin procesos ni sockets:

- `SSL_CTX_new(TLS_server_method())`, `SSL_CTX_set_psk_server_callback`
  (devuelve el PSK cero y acepta cualquier identidad; el sensor manda
  `"Client_identity"`).
- Dos BIOs de memoria (`BIO_s_mem`, con `BIO_set_mem_eof_return(-1)`) como
  transporte: lo que llega del sensor en packs `0xB0` se escribe en uno; lo que
  OpenSSL produce se lee del otro y se envía en packs `0xB0`, sin ACK.
- Secuencia observada: ClientHello (el sensor ofrece solo `0x00ae`
  = PSK-AES128-CBC-SHA256) → ServerHello + ServerHelloDone →
  ClientKeyExchange, ChangeCipherSpec, Finished (tres packs) →
  ChangeCipherSpec + Finished. Tras el último envío se esperan 10 ms
  (goodix-fp-dump lo hace para evitar un timeout USB).
- Resultado: **TLS 1.2, PSK-AES128-CBC-SHA256**. La sesión queda en
  `self->tls` y solo se usa para descifrar imágenes.

Nota: la configuración y los demás comandos **no** pasan por TLS; solo la
respuesta de imagen.

### 4.7 Captura de imagen

`mcu_get_image` es un comando normal. La respuesta es un pack `0xB2` de 7758
bytes de datos:

```
00 20 4a 1e 00 00 00 00 00 | 17 03 03 1e 40 …
└── prefijo de 9 bytes ──┘   └── registro TLS 1.2 de datos de aplicación
```

En las capturas vistas, el prefijo es `[00][20 = cmd][longitud de lo que sigue
tras los 4 primeros bytes, LE16][00 ×5]`. El driver comprueba que tras el
prefijo haya `17 03 03`, descifra los 7749 bytes de registros con `SSL_read` y
obtiene **7684 bytes**; se descartan los 4 últimos (como el script) y quedan
7680 bytes = 5120 píxeles de 12 bits.

Decodificación (igual que `tool.decode_image`), 6 bytes → 4 píxeles:

```
p0 = ((b0 & 0xF) << 8) | b1        p1 = (b3 << 4) | (b0 >> 4)
p2 = ((b5 & 0xF) << 8) | b2        p3 = (b4 << 4) | (b5 >> 4)
```

**Geometría**: los píxeles forman **64 columnas × 80 filas**. En
`driver_5503.py` las constantes se llaman al revés (`SENSOR_WIDTH = 80`,
`SENSOR_HEIGHT = 64`), pero su `write_pgm` escribe filas de 64. SIGFM recibía
80×64 al principio (filas desalineadas); se corrigió en `private.h`.

Valores típicos de un frame crudo: sin dedo, media ~1150-1170; con dedo,
~220-490 (hasta ~740 si solo apoya parte).

### 4.8 Configuración y payloads FDT

`DEVICE_CONFIG` mide **256 bytes** (no 272) y se envía tal cual. La plantilla
la "parcheaba" con valores de OTP de la 53x5 salvo si medía 272, lo que en la
práctica corrompía el checksum; se envía sin parchear.

Payloads FDT (de `driver_5503.py`):
`[op][01][registros 8b 84 8c 88 en LE16][6 umbrales en LE16 con byte bajo 0x80]`.

| Uso | op | Umbrales (byte alto) |
|---|---|---|
| fdt_mode antes de la referencia y para sondear | `0d` | 96 91 92 85 8c 86 |
| fdt_mode tras capturar | `0d` | b9 ae b9 af b5 aa |
| fdt_down (Python lo usa para esperar el dedo) | `0c` | b9 ae b9 af b5 aa |
| fdt_down final ("idle") | `0c` | ba af ba b0 b6 ab |
| fdt_up #1 / #2 (no se usan) | `0e` | 95 89 99 8a 8d 8d / 9b 8e a2 90 9f a8 |

Las respuestas FDT traen `[02][00 o 01][máscara 3f 00][6 lecturas LE16]`, una
lectura por zona del sensor.

---

## 5. Detección de dedo

### 5.1 Por qué no se usan los eventos FDT del sensor

`driver_5503.py` espera el dedo con `mcu_switch_to_fdt_down(…, reply=True)`
y toma cualquier respuesta `0x32` como "dedo detectado". En el hardware real,
**sin dedo**, esa respuesta llega siempre ~34 ms después de armar:

| Prueba (sin dedo) | ¿Llega el `0x32`? |
|---|---|
| Umbrales de Python, armado doble | sí, a los 34 ms |
| Umbrales = lectura base + 0x10 | sí |
| Umbrales = lectura base − 20 | sí |
| Umbrales 0xff | sí |
| Un solo armado | sí |

Es una respuesta incondicional ("armado, estas son las lecturas"), no una
detección. El script solo "funciona" si el dedo ya está puesto. Con un sondeo
de diagnóstico (fase pasiva de 20 s tras armar), **tocar el sensor no produjo
ningún mensaje adicional**. Con los umbrales de Python, `fdt_up` sin dedo nunca
respondió en 20 s (probable causa del cuelgue en `mcu_switch_to_fdt_up` del
issue 43 de goodix-fp-dump). Los otros drivers de goodix-fp-dump siguen el
mismo patrón con umbrales copiados de capturas de Windows.

### 5.2 Qué cambia realmente con un dedo

Se sondearon las lecturas de `fdt_mode` (4 veces por segundo durante 30 s,
122 ciclos: 84 sin dedo y 38 con dedo; la media del frame sirvió de verdad de
referencia):

| | Zona 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| Sin dedo, media | 176.8 | 148.0 | 202.5 | 165.4 | 191.3 | 155.6 |
| Sin dedo, desviación típica | 0.5 | 0.5 | 0.6 | 0.6 | 0.6 | 0.6 |
| Toque firme (ejemplo) | 49 | 54 | 95 | 5 | 36 | 45 |
| Punta del dedo (ejemplo) | 175 | 147 | 80 | 140 | 85 | 76 |

- El dedo **baja** las lecturas. Sin dedo, ninguna zona se aleja más de 2.6 de
  su media; con contacto real, la zona más afectada cae **89 o más**.
- La punta solo cubre las zonas 2-5: la regla debe mirar *cualquier* zona.
- Las cabeceras (`02 01` / `02 00`) y la máscara `3f` nunca cambian: no hay un
  flag de "toque".
- Entre ejecuciones la base varía unos pocos puntos: se mide en cada espera.

### 5.3 Algoritmo (sondeo, `scan.c`)

Cada ~100 ms (período medido: 9.9 Hz, ~1 % de CPU) se envía `fdt_mode` y se
leen las 6 zonas.

- **Espera de dedo**: la primera lectura es la **base sin dedo**. Dedo puesto
  si **alguna** zona queda **≥ 20** por debajo de la base en **2 lecturas
  seguidas** (esas ~100-200 ms dejan que la presión se asiente antes de
  capturar).
- **Espera de retirada**: dedo retirado si **todas** las zonas vuelven a
  **≤ 10** de la base (la de la espera de dedo del mismo ciclo, no una lectura
  tomada con el dedo puesto) en **2 lecturas seguidas**. El margen entre 20 y
  10 evita oscilaciones.
- **Recuperación**: si alguna zona **sube ≥ 20** por encima de la base en 2
  lecturas, el dedo ya estaba puesto cuando se tomaron la base y la imagen de
  referencia (por ejemplo, un toque rápido justo tras retirarlo). Se vuelven a
  capturar referencia y base y se sigue esperando. Sin esto la espera quedaba
  colgada para siempre.
- **Cancelación**: se comprueba el `GCancellable` de la acción antes de cada
  lectura (≤ 100 ms de latencia). No hay lecturas USB bloqueantes, así que la
  suspensión del sistema se completa de inmediato.
- **Cierre**: tras la retirada (o tras un verify correcto) se replica la cola
  de `driver_5503.py`: `fdt_down` "idle", consumir su `0x32` inmediato y
  `query_mcu_state(01 00 32)`.
- El transporte descarta cualquier evento FDT (`0x32`/`0x34`) que llegue donde
  se esperaba un ACK.

### 5.4 Resultados

- Sin dedo: 0 falsos positivos (caídas entre −2 y +2 en cientos de lecturas).
- Cada toque se detectó una lectura después del contacto (~100 ms) y la
  captura llegó ~37 ms después.
- Retirada lenta con el sensor medio cubierto 1-3 s: las zonas cubiertas
  seguían 40-160 por debajo, así que nunca hubo retirada prematura ni
  oscilación. La cobertura por zona es casi binaria, por lo que el margen
  20/10 casi no llegó a actuar.
- Toques rápidos repetidos: la recuperación se disparó 3 veces; las
  referencias contaminadas (media 304-343) se sustituyeron por limpias
  (1128-1130) y el siguiente toque se detectó.

---

## 6. Imagen y matching

### 6.1 Preprocesado

Antes de cada espera se captura un frame **sin dedo** (referencia, el "clear"
de `driver_5503.py`). La captura con dedo se resta de la referencia y se
normaliza a 8 bits con los percentiles 3-97 % del interior
(`goodix_device_image_to_8bit`). SIGFM aplica CLAHE (4.0, 4×4) y extrae SIFT.

### 6.2 SIGFM y su escala de puntuación

Parámetros: `distance_match 0.85`, `length_match 0.05`, `angle_match 0.05`,
`min_match 5`, SIFT (contraste 0.04, bordes 18, sigma 2.0). La puntuación
cuenta **pares de pares de coincidencias** coherentes en distancia y rotación,
así que crece aproximadamente como M⁴/8 para M coincidencias coherentes. El
umbral `GOODIX_SIGFM_BEST_MIN = 150` equivale a unas 6-7 coincidencias. Una
plantilla son las 8 muestras del enroll; verify toma la mejor puntuación.

### 6.3 Enroll

8 muestras (`GOODIX_ENROLL_SAMPLES`); se rechaza una muestra con menos de 20
puntos clave SIFT. El filtro de la plantilla 53x5 por "fracción recortada"
(píxeles saturados a 4095) **nunca actúa en el 5503**, porque sus frames no se
saturan.

### 6.4 Precisión medida

| Plantilla | Dedo registrado | Otro dedo |
|---|---|---|
| Enroll con el dedo siempre en el centro | 8/16 aceptados | 0/5 (máx. 34) |
| Enroll recorriendo zonas | 2/4 | 0/4 (máx. 1) |

Las puntuaciones son "todo o nada": las coincidencias van de 2387 a 483404;
los fallos del dedo registrado, de 0 a 16. **Bajar el umbral no ayuda**: los
fallos puntúan por debajo de lo que llegó a puntuar otro dedo (34).

La causa es de **cobertura**: el sensor ve una parte pequeña del dedo. El
centro de la yema se reconoce; la punta y los costados fallan si no están en la
plantilla. En la práctica (igual que con el driver de Windows) basta con volver
a tocar. Midiendo la cobertura de contacto de las muestras (píxeles al menos
300 más oscuros que la referencia), las buenas cubren el 93-99 % del sensor y
las parciales (punta, medio vacías) el 43-83 %.

Mejoras propuestas y aplazadas (sección 12): filtro de cobertura ≥ ~85 % en el
enroll y subir a 16 muestras.

---

## 7. Compilar, probar e instalar

### 7.1 Compilar

Dependencias además de las de libfprint: OpenSSL ≥ 3.0 (`libssl-dev`) y
OpenCV 4 (`libopencv-dev`: core, features2d, flann, imgproc). Se probó con
OpenSSL 3.0.2 y OpenCV 4.5.4.

libfprint exige **meson ≥ 0.62**; el de Ubuntu 22.04 / Mint 21 es el 0.61.2.
Se usó meson 1.12 instalado con pip en un entorno virtual:

```bash
python3 -m venv ~/meson-venv && ~/meson-venv/bin/pip install meson ninja
~/meson-venv/bin/meson setup build -Ddrivers=goodix53x5
ninja -C build
```

Con la lista de drivers por defecto hace falta además `libudev-dev` (la
exige el driver SPI `elanspi`); con `-Ddrivers=goodix53x5` no.

### 7.2 Pruebas sin fprintd

Para usar los ejemplos de libfprint sin root hace falta dar acceso al
dispositivo con la regla udev de desarrollo `tools/70-goodix5503.rules`
(**quitarla al terminar**, sección 11). fprintd debe estar parado
(`systemctl is-active fprintd`).

Los ejemplos se ejecutan desde `build/` y guardan sus plantillas en
`build/test-storage.variant` (una por dedo). Piden el dedo por la entrada
estándar (índice del menú, 6 = índice derecho):

```bash
cd build
printf '6\nn\n' | ./examples/enroll
./examples/verify          # interactivo: dedo, y "Verify again? [Y/n]"
```

Detalles prácticos:

- Los ejemplos activan `G_MESSAGES_DEBUG=all` por su cuenta y GLib escribe la
  depuración en **stdout**. Para filtrar: `… 2>&1 | tee log | grep --line-buffered …`.
- El prompt `Verify again?` no termina en salto de línea, así que un `grep`
  lo oculta. Para pruebas repetidas usar `tools/verify-loop.sh`, que ejecuta
  verify una vez por intento y anota qué dedo se usó.
- Tras un `MATCH!` el driver no espera a que se retire el dedo; retirarlo
  antes de iniciar otro intento.
- `GOODIX5503_DUMP_DIR` guarda los frames como PGM y `GOODIX5503_FDT_DEBUG=1`
  registra cada lectura del sondeo (sección 10).

### 7.3 Instalar

En este sistema fprintd carga libfprint desde `/usr/local/lib/x86_64-linux-gnu/`
(comprobar con `ldd /usr/libexec/fprintd | grep fprint`). La copia de
`/usr/lib/x86_64-linux-gnu/` (paquete `libfprint-2-2`) se ignora.

```bash
mkdir -p ~/libfprint-backup
cp -a /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0 ~/libfprint-backup/libfprint-2.so.2.0.0-$(date +%F)
sudo systemctl stop fprintd
sudo install -m 755 build/libfprint/libfprint-2.so.2.0.0 /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0
sudo ldconfig
ls -la /usr/local/lib/x86_64-linux-gnu/libfprint-2.so*
cmp build/libfprint/libfprint-2.so.2.0.0 /usr/local/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0 && echo OK
```

- Guardar las copias de seguridad **fuera** de esa carpeta: `ldconfig` puede
  hacer que `libfprint-2.so.2` apunte a un `.bak` que esté a su lado.
- Tras instalar hay que registrar la huella con `fprintd-enroll`; las
  plantillas de los ejemplos no se comparten con fprintd.
- Volver atrás: `sudo install` de la copia de seguridad + `sudo ldconfig`.

---

## 8. fprintd, PAM y el inicio de sesión

```bash
fprintd-enroll -f right-index-finger
fprintd-verify
sudo apt install libpam-fprintd
sudo pam-auth-update            # marcar "Fingerprint authentication"
```

- El perfil de Mint escribe `pam_fprintd.so max-tries=1 timeout=10` en
  `/etc/pam.d/common-auth` (1 intento, 10 s). En este equipo se subió a
  `max-tries=3 timeout=30`. Tras agotarse, se pide la contraseña; en una
  terminal, Ctrl+C salta a la contraseña.
- El mensaje de fprintd es "Place your … finger on <nombre del dispositivo>".
  La pantalla de inicio (LightDM + slick-greeter) lo recortaba con el nombre
  de la plantilla ("Goodix HTK32 Fingerprint Sensor"); por eso `full_name` es
  ahora "Goodix 5503".
- slick-greeter muestra el campo de contraseña y a la vez el mensaje de huella;
  mientras `pam_fprintd` espera, la contraseña solo se acepta después de que la
  huella se rinda.
- **Llavero de GNOME**: al entrar con huella no hay contraseña para
  desbloquearlo y se pide aparte ("login keyring did not get unlocked"). Es
  el comportamiento normal en Linux. Opciones: mantenerlo (se pide una vez
  por sesión; la elegida aquí), quitarle la contraseña con Seahorse (sin
  cifrar en disco) o usar solo contraseña en la pantalla de inicio. Guardar la
  contraseña de usuario para "rellenarla" tras la huella se descartó: da acceso
  de root a quien la lea. Un desbloqueo sellado con el TPM (el equipo tiene
  TPM 2.0) aporta poco mientras el disco no esté cifrado.
- Para quitar la huella solo de la pantalla de inicio, sustituir
  `@include common-auth` en `/etc/pam.d/lightdm` por una copia explícita de
  las líneas de contraseña de `common-auth`. **No** usar el truco de "saltar
  la primera línea": si la huella se desactivara, saltaría la contraseña y
  bloquearía el acceso.

---

## 9. Arranque dual con Windows (PSK)

El driver de Windows provisiona **su propio PSK** en el sensor. Al inicio de
este trabajo el sensor tenía el hash `2c26e305…` (ni el PSK cero ni el de
`driver_5503.py`) aunque el script Python ya se había ejecutado antes. La
primera apertura del driver escribió el PSK cero; desde entonces el hash es
`81b8ff49…` (`PMK_HASH`). La escritura se hizo opcional para no pisarle el PSK
a Windows en cada apertura.

**Comportamiento comprobado:**

- Windows escribe un PSK **nuevo** cada vez que encuentra uno que no es suyo.
  Tras la primera escritura del PSK cero, un arranque de Windows dejó el hash
  `5104d34c…`, distinto del `2c26e305…` original. **Windows Hello siguió
  reconociendo la huella** sin volver a registrarla.
- Sin permiso de escritura, Linux falla de forma limpia al volver: en
  `journalctl -u fprintd` aparece `PSK mismatch, write skipped` y el TLS
  termina con `bad record mac`. La huella queda no disponible, pero las
  plantillas de fprintd no se pierden (no dependen del PSK).

**Configuración recomendada con arranque dual:** dejar que fprintd reescriba el
PSK con un drop-in de systemd
([`tools/goodix5503-psk.conf`](tools/goodix5503-psk.conf)):

```bash
sudo mkdir -p /etc/systemd/system/fprintd.service.d
sudo cp docs/goodix5503/tools/goodix5503-psk.conf /etc/systemd/system/fprintd.service.d/
sudo systemctl daemon-reload && sudo systemctl restart fprintd
systemctl show fprintd -p Environment     # debe mostrar GOODIX5503_ALLOW_PSK_WRITE=1
```

Así, el primer uso de la huella tras volver de Windows registra
`PSK mismatch and GOODIX5503_ALLOW_PSK_WRITE=1: writing PSK white box` y
funciona con normalidad; Windows hace lo mismo por su lado. Probado en este
equipo. Cada cambio de sistema supone una escritura en la flash del sensor,
asumible con un uso normal.

Para deshacerlo:
`sudo rm /etc/systemd/system/fprintd.service.d/goodix5503-psk.conf && sudo systemctl daemon-reload && sudo systemctl restart fprintd`.

Sin el drop-in, se puede reescribir el PSK una sola vez a mano con los
ejemplos: `printf '6\n' | GOODIX5503_ALLOW_PSK_WRITE=1 ./examples/verify`
desde `build/`, y Ctrl+C al llegar a `Waiting for finger down`.

---

## 10. Variables de entorno

| Variable | Efecto |
|---|---|
| `GOODIX5503_ALLOW_PSK_WRITE=1` | Permite escribir el PSK cero si el del sensor no coincide (persistente) |
| `GOODIX5503_DUMP_DIR=<dir>` | Guarda cada frame como `clear-N.pgm` / `finger-N.pgm` (formato de `tool.write_pgm`); la numeración empieza en 0 en cada proceso |
| `GOODIX5503_FDT_DEBUG=1` | Registra cada lectura del sondeo (`FDT-POLL …`: zonas, caídas, contador) |

Todo lo demás se registra a nivel depuración (`G_MESSAGES_DEBUG=all`): cada
transferencia USB en hexadecimal (`USB TX` / `USB RX`), el handshake TLS paso
a paso y los cambios de estado del sondeo. Una apertura normal no emite avisos.

---

## 11. Seguridad

- **PSK público**: el PSK es el de 32 ceros usado por goodix-fp-dump. Quien
  pueda hablar con el sensor por USB puede establecer la sesión TLS y
  descifrar imágenes. Con fprintd solo root accede al dispositivo; la regla
  udev de desarrollo (`MODE="0666"`) lo abre a cualquier proceso local y debe
  eliminarse al terminar.
- **PGM de diagnóstico**: son imágenes de huella (datos biométricos). No se
  incluyen en este repositorio y no deben publicarse.
- **Plantillas**: fprintd guarda las características SIGFM en
  `/var/lib/fprint/` (solo root).

---

## 12. Limitaciones y trabajo pendiente

**Antes de proponer el driver a libfprint:**

- `goodix53x5_id_table` todavía incluye `0x5335`, `0x5385` y `0x5395`, pero el
  driver ya solo habla el protocolo del 5503: esos sensores dejarían de
  funcionar. Hay que quitarlos o separar el 5503 en un driver propio.
- Código heredado sin uso en el 5503: GTLS (`crypto.c`), cálculo de OTP/FDT
  (`calibration.c`), comandos 53x5 (`fdt_manual`, `request_image`,
  `ec_control`, `mcu_send`, …) y parte de la lógica de suspensión del
  transporte pensada para lecturas bloqueantes.
- El driver se llama `goodix53x5`; renombrarlo cambiaría la ruta de las
  plantillas en fprintd (`/var/lib/fprint/<usuario>/<driver>/…`).

**Funcionalidad:**

- Sin probar: bloqueo de pantalla y suspender/reanudar.
- Cobertura del enroll: filtro de cobertura de contacto (rechazar muestras con
  menos del ~85 %) y 16 muestras en lugar de 8. Aplazado a propósito: en la
  práctica basta con volver a tocar.
- `GOODIX5503_DUMP_DIR` sobrescribe los archivos entre procesos (la
  numeración reinicia); convendría añadir la hora al nombre.
- La semántica real de `fdt_down` / `fdt_up` como interrupción del sensor
  sigue sin conocerse. Una captura USB de Windows Hello (USBPcap; goodix-fp-dump
  incluye un disector de Wireshark) mostraría cómo calcula Windows los umbrales
  y permitiría esperar el dedo sin sondear (menos consumo).
- El OTP no se interpreta y no se usa ninguna calibración por sensor.
- Solo se ha probado una unidad de 27c6:5503.

---

## 13. Historia del proyecto

Resumen de los hallazgos en orden, útil para no repetir caminos ya descartados.

1. **Punto de partida.** Carpeta de la plantilla goodix53x5 con el PID 0x5503
   añadido. La interfaz se reclamaba bien, pero el primer ping daba timeout.
2. **Protocolo equivocado.** Comparando byte a byte con `goodix.py`: el 5503
   espera message packs `0xA0`, escrituras de 64 bytes, un nop sin checksum y
   sin ACK obligatorio; la plantilla usaba el protocolo wrapless (interfaz
   CDC 1). Reescrito el transporte; la apertura llegó hasta el PSK.
3. **PSK y Windows.** El sensor tenía un PSK desconocido; la primera apertura
   lo sobrescribió con el PSK cero. Se hizo la escritura opcional.
4. **TLS.** El sensor es cliente TLS-PSK; se implementó el servidor con BIOs
   de memoria de OpenSSL. El flag del handshake es `0xB0`, no `0xB2`.
5. **Configuración y primera imagen.** `DEVICE_CONFIG` mide 256 bytes (el
   parcheo 53x5 lo habría corrompido). La imagen llega en un pack `0xB2`
   (prefijo de 9 bytes + TLS) y se descifra a 7684 bytes. Las imágenes de
   referencia del proyecto Python resultaron tener el dedo puesto en todas.
6. **Captura en scan.c y geometría.** Se reutilizó el patrón de sub-SSMs de la
   plantilla. La imagen es 64×80, no 80×64.
7. **Detección de dedo.** El `0x32` tras `fdt_down` es incondicional
   (experimentos de 5.1). Un sondeo de diagnóstico con el usuario tocando el
   sensor mostró que el dedo baja las lecturas de las zonas; se sustituyó la
   espera por eventos por un sondeo de `fdt_mode` a 10 Hz con umbrales
   medidos.
8. **Enroll y verify.** Primer enroll completo 8/8. Verify: sin falsos
   positivos; falsos negativos por cobertura del sensor, aceptados.
9. **Instalación.** Limpieza de avisos de depuración; corrección del cuelgue
   por toques rápidos (referencia tomada con el dedo puesto); PAM; nombre
   corto del dispositivo para la pantalla de inicio; decisión sobre el llavero.
10. **Arranque dual.** Tras un arranque de Windows, el sensor tenía un PSK
    nuevo y Linux falló como estaba previsto (sin escribir nada). Windows Hello
    había seguido funcionando, así que se activó la reescritura automática en
    fprintd con un drop-in de systemd; desde entonces la huella funciona en
    los dos sistemas.

---

## 14. Herramientas de análisis

En `docs/goodix5503/tools/`:

| Herramienta | Uso |
|---|---|
| `fdt_poll_analysis.py LOG` | Resumen de cada espera de un log con `GOODIX5503_FDT_DEBUG=1`: lecturas antes del toque, reinicios del contador en la retirada, recuperaciones |
| `verify_analysis.py LOG` | Tabla de un log de `verify-loop.sh`: detección, puntuación por muestra, resultado, aciertos por tipo de dedo |
| `verify-loop.sh [DEDO] [LOG]` | Verify repetido y etiquetado, desde `build/` |
| `coverage.py DIR [UMBRAL]` | Cobertura de contacto de pares `clear-N`/`finger-N` de `GOODIX5503_DUMP_DIR` |
| `pgm_montage.py OUT.png A.pgm …` | Frames lado a lado en un PNG (requiere Pillow) |
| `70-goodix5503.rules` | Regla udev de desarrollo (solo pruebas) |
| `goodix5503-psk.conf` | Drop-in de systemd para que fprintd reescriba el PSK tras usar Windows (sección 9) |

Ejemplo de prueba de detección:

```bash
cd build
printf '3\nn\n' | GOODIX5503_FDT_DEBUG=1 ./examples/enroll 2>&1 | tee ~/poll.log |
  grep --line-buffered -oE "Waiting for finger (down|up)|Finger (down|up) detected.*|retaking.*|Enroll stage.*"
../docs/goodix5503/tools/fdt_poll_analysis.py ~/poll.log
```

---

## 15. Referencias

- goodix-fp-dump (protocolo, `driver_5503.py`, MIT):
  <https://github.com/goodix-fp-linux-dev/goodix-fp-dump> (commit `cc43bb3`)
- goodix53x5-libfprint (plantilla, LGPL-2.1):
  <https://github.com/AndyHazz/goodix53x5-libfprint> (commit `309d4c6`)
- SIGFM (LGPL-2.1+): incluido en la plantilla, `libfprint/sigfm/`
- libfprint: <https://gitlab.freedesktop.org/libfprint/libfprint>
  (base: `6f9479c3`)
