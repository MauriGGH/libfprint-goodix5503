/*
 * Goodix 53x5 driver for libfprint — Private device state
 * Copyright (C) 2024 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"

#include "goodix53x5.h"
#include "goodix53x5-proto.h"
#include "goodix53x5-crypto.h"
#include "goodix53x5-tls.h"

/* USB interface claimed at open and released at close — interface 0 for 5503 */
#define GOODIX_USB_INTERFACE 0

/* Sensor dimensions: 64 columns x 80 rows in decode order. driver_5503.py
 * calls these SENSOR_HEIGHT and SENSOR_WIDTH the other way round, but its
 * write_pgm() emits rows of 64 pixels. */
#define GOODIX_SENSOR_WIDTH  64
#define GOODIX_SENSOR_HEIGHT 80
#define GOODIX_SENSOR_PIXELS (GOODIX_SENSOR_WIDTH * GOODIX_SENSOR_HEIGHT)
#define GOODIX_SENSOR_RAW12_BYTES (((GOODIX_SENSOR_PIXELS + 3) / 4) * 6)

/* FDT base length */
#define GOODIX_FDT_BASE_LEN 24

/* FDT zone readings in a 5503 fdt_mode reply */
#define GOODIX_FDT_ZONES 6

/* Enroll stages */
#define GOODIX_ENROLL_SAMPLES 8

/* SIGFM (SIFT-based) matching parameters.
 * This gate is tuned for TX-off p3 preprocessing plus mutual SIGFM matching;
 * it is not comparable to old p2/p3 non-mutual score scales.
 */
#define GOODIX_SIGFM_BEST_MIN 150  /* minimum best score from any single sample */

/* Captures below this feature count are effectively blank/failed touches. */
#define GOODIX_MIN_CAPTURE_KEYPOINTS 20

/* Raw12 frames hard-clip at ADC full scale wherever the finger is not in
 * contact, so clipped pixels carry no finger signal. The TX-off subtraction
 * cannot cancel the fixed sensor grid there (residual = clip - ref), so
 * preprocessing fills clipped pixels with a white level taken from the
 * unclipped interior instead of letting the inverted reference grid through. */
#define GOODIX_RAW12_CLIP 4095

/* Clipped fraction doubles as an exact contact-coverage metric. Enrollment
 * stages with more than this fraction of non-contact pixels are rejected with
 * a retry so stored templates keep full ridge coverage. */
#define GOODIX_ENROLL_MAX_CLIPPED_FRACTION 0.10

/* PSK white box for writing all-zero PSK */
#define GOODIX_PSK_WHITE_BOX_LEN 96

/* PSK and PMK constants for sensor 5503 */
#define GOODIX_PSK_READ_FLAGS 0xbb020007
#define GOODIX_PSK_WRITE_FLAGS 0xbb010003
#define GOODIX_PMK_HASH_LEN 32

/* --- Calibration parameters (from OTP) --- */
typedef struct
{
  guint16 tcode;
  guint16 delta_fdt;
  guint16 delta_down;
  guint16 delta_up;
  guint16 delta_img;
  guint16 delta_nav;
  guint16 dac_h;
  guint16 dac_l;
  guint16 dac_delta;
  guint8  fdt_base_down[GOODIX_FDT_BASE_LEN];
  guint8  fdt_base_up[GOODIX_FDT_BASE_LEN];
  guint8  fdt_base_manual[GOODIX_FDT_BASE_LEN];
} GoodixCalibParams;

/* --- Command descriptor for sub-SSM --- */
typedef struct
{
  guint8  category;
  guint8  command;
  guint8 *payload;
  gsize   payload_len;
  gboolean use_checksum;
  gboolean ack_optional; /* a missing ACK is not an error (nop) */
} GoodixCmd;

/* --- Device struct --- */
struct _FpiDeviceGoodix53x5
{
  FpDevice parent;

  GCancellable *cancel;

  /* GTLS session (persists across captures) */
  GoodixGtlsCtx gtls;

  /* TLS-PSK session with the 5503 (set up during open) */
  GoodixTls *tls;

  /* Calibration (from OTP, persists across captures) */
  GoodixCalibParams calib;

  /* Reassembly buffer for multi-chunk reads */
  GoodixReassembly rx;
  GCancellable    *rx_cancellable; /* Cancellable for current receive */
  guint            rx_timeout;     /* Timeout for current receive continuation */
  gboolean         rx_timeout_ok;  /* Timeout before any data completes the SSM */

  /* Temporary data used during SSMs */
  guint8  *fdt_event_data;     /* FDT event data (24 bytes) */
  guint16  fdt_touch_flag;
  gint64   fdt_wait_start;     /* monotonic time the current FDT wait began */

  /* Finger detection by polling the FDT zone readings (see scan.c) */
  guint16  fdt_baseline[GOODIX_FDT_ZONES]; /* no-finger readings */
  gboolean fdt_have_baseline;
  guint    fdt_consecutive;    /* polls in a row meeting the target state */
  guint    fdt_rise_consecutive; /* polls in a row above the baseline */
  gint64   fdt_poll_start;     /* monotonic time the current poll began */
  gboolean fdt_debug;          /* GOODIX5503_FDT_DEBUG=1: log every poll */

  /* Sequence number for GOODIX5503_DUMP_DIR frame dumps */
  guint dump_seq;

  /* Temporary FDT data from calibration */
  guint8 *fdt_data_tx_on;
  guint8  open_fdt_retries;

  /* OTP raw data */
  guint8 *otp_data;
  gsize   otp_len;

  /* Firmware version string */
  gchar *fw_version;

  /* TRUE while verifying a PSK write during open. */
  gboolean psk_write_verify_pending;

  /* TRUE if the device PSK did not match and the write was skipped. */
  gboolean psk_mismatch;

  /* Current command (for sub-SSM) */
  GoodixCmd *cmd;

  /* USB interface state */
  gboolean usb_interface_claimed;

  /* System sleep happened while the device was open; the USB claim and GTLS
   * session may be stale (S4 reset/re-enumeration rebinds cdc_acm). The next
   * verify/identify/enroll runs the full open SSM before any auth USB I/O. */
  gboolean needs_reinit;

  /* Task SSM tracking */
  FpiSsm *task_ssm;

  /* TRUE once verify/identify has already reported a result. */
  gboolean action_result_reported;

  /* Failed verify/identify attempts wait for lift-off before completing so one
   * held invalid finger cannot consume multiple PAM attempts. */
  gboolean verify_wait_finger_up;

  /* Verify/identify result queued until post-match cleanup has completed. */
  gboolean        pending_result_report;
  FpiDeviceAction pending_result_action;
  FpiMatchResult  pending_verify_result;
  FpPrint        *pending_identify_match;
  GError         *pending_result_error;
  GError         *pending_action_error;

  /* Suspend/resume state */
  gboolean suspend_pending;      /* suspend() cancelled the blocking read and
                                  * the rx callback owes suspend_complete() */
  FpiSsm  *blocking_ssm;        /* Sub-SSM currently blocked on cancellable read */
  int      blocking_resume_state; /* SSM state to jump to on resume */
  int      blocking_shutdown_state; /* SSM state the RX callback jumps to when
                                     * libfprint cancels after the action result
                                     * was already reported (sensor shutdown) */

  /* Captured images from last scan */
  guint16 *reference_image; /* native 80x64 12-bit TX-off no-finger frame */
  guint8  *captured_image;  /* native 80x64 8-bit processed frame */
  double   captured_clipped_fraction; /* non-contact (clipped) pixel fraction */

  /* Enrollment tracking */
  GPtrArray *enroll_features; /* array of GBytes* serialized SIGFM features */
  gint       enroll_stage;
};
