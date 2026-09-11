/*
 * Goodix 53x5 driver for libfprint — Scan flow (FDT finger detection and capture)
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

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "goodix53x5-private.h"
#include "goodix53x5-transport.h"
#include "goodix53x5-commands.h"
#include "goodix53x5-image.h"
#include "goodix53x5-scan.h"

#include <stdlib.h>
#include <string.h>

/* Debug: directory to save every decoded frame as PGM */
#define GOODIX_DUMP_DIR_ENV "GOODIX5503_DUMP_DIR"

/* Debug: log every FDT poll with its zone readings */
#define GOODIX_FDT_DEBUG_ENV "GOODIX5503_FDT_DEBUG"

/* driver_5503.py drops this many bytes of 0xB2 pack data before handing the
 * rest (TLS records) to the TLS server */
#define GOODIX_IMAGE_TLS_OFFSET 9

/*
 * Finger detection polls the six FDT zone readings returned by fdt_mode.
 * The sensor's own FDT events can't be used: it answers fdt_down right after
 * arming whatever the thresholds, and sent nothing when touched afterwards.
 * A finger lowers the readings. Over 122 probed cycles, no-finger readings
 * stayed within 2.6 of their mean while real contact lowered the most
 * affected zone by 89 or more; a fingertip only covers zones 2-5.
 */
#define GOODIX_FDT_POLL_PERIOD 100 /* ms between poll starts */
#define GOODIX_FDT_DOWN_DROP   20  /* any zone this far below baseline: finger */
#define GOODIX_FDT_UP_MARGIN   10  /* every zone this close to baseline: no finger */
#define GOODIX_FDT_CONSECUTIVE 2   /* polls in a row before changing state */

/* The idle fdt_down arm is answered right away (see above) */
#define GOODIX_FDT_ARM_REPLY_TIMEOUT 200

/*
 * Payloads from driver_5503.py run_driver(). The FDT ones are
 * [op][0x01][registers 8b 84 8c 88 as LE16][six FDT thresholds as LE16].
 */
#define GOODIX_FDT_REGS 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00

/* Before a no-finger (reference) frame; also used to poll the zones */
static const guint8 fdt_mode_clear[] = {
  0x0d, 0x01, GOODIX_FDT_REGS,
  0x80, 0x96, 0x80, 0x91, 0x80, 0x92, 0x80, 0x85, 0x80, 0x8c, 0x80, 0x86,
};

/* After a finger frame ("Finger scanned, reset sensor") */
static const guint8 fdt_mode_down[] = {
  0x0d, 0x01, GOODIX_FDT_REGS,
  0x80, 0xb9, 0x80, 0xae, 0x80, 0xb9, 0x80, 0xaf, 0x80, 0xb5, 0x80, 0xaa,
};

/* Final arm that leaves the sensor idle */
static const guint8 fdt_down_idle[] = {
  0x0c, 0x01, GOODIX_FDT_REGS,
  0x80, 0xba, 0x80, 0xaf, 0x80, 0xba, 0x80, 0xb0, 0x80, 0xb6, 0x80, 0xab,
};

static const guint8 get_image_request[] = {
  0x01, 0x00, GOODIX_FDT_REGS,
};

static const guint8 query_mcu_state_idle[] = { 0x01, 0x00, 0x32 };

/* No-finger reference capture SSM */
typedef enum {
  GOODIX_REF_CAPTURE_FDT_MODE = 0,
  GOODIX_REF_CAPTURE_GET_IMAGE,
  GOODIX_REF_CAPTURE_DECODE,
  GOODIX_REF_CAPTURE_NUM_STATES,
} GoodixRefCaptureState;

/* Finger-wait SSM (polling for finger down) */
typedef enum {
  GOODIX_FINGER_WAIT_START = 0,
  GOODIX_FINGER_WAIT_POLL,
  GOODIX_FINGER_WAIT_EVAL,
  GOODIX_FINGER_WAIT_RECAPTURE_REF,
  GOODIX_FINGER_WAIT_RECAPTURE_DONE,
  GOODIX_FINGER_WAIT_NUM_STATES,
} GoodixFingerWaitState;

/* Capture SSM */
typedef enum {
  GOODIX_CAPTURE_GET_IMAGE = 0,
  GOODIX_CAPTURE_DECODE,
  GOODIX_CAPTURE_NUM_STATES,
} GoodixCaptureState;

/* Finger-up SSM (polling for finger off, then leaving the sensor idle) */
typedef enum {
  GOODIX_FINGER_UP_START = 0,
  GOODIX_FINGER_UP_POLL,
  GOODIX_FINGER_UP_EVAL,
  GOODIX_FINGER_UP_IDLE_ARM,
  GOODIX_FINGER_UP_IDLE_ARM_REPLY,
  GOODIX_FINGER_UP_QUERY_MCU_STATE,
  GOODIX_FINGER_UP_DONE,
  GOODIX_FINGER_UP_NUM_STATES,
} GoodixFingerUpState;

/* Deactivate SSM — bounded cleanup after successful verify/identify */
typedef enum {
  GOODIX_DEACTIVATE_FDT_MODE = 0,
  GOODIX_DEACTIVATE_IDLE_ARM,
  GOODIX_DEACTIVATE_IDLE_ARM_REPLY,
  GOODIX_DEACTIVATE_QUERY_MCU_STATE,
  GOODIX_DEACTIVATE_DONE,
  GOODIX_DEACTIVATE_NUM_STATES,
} GoodixDeactivateState;

/* ========================================================================
 * Helpers
 * ======================================================================== */

/* Parse the reply of the previous command, failing @ssm if it is not
 * @category/@command. */
static gboolean
goodix_scan_expect_reply (FpiSsm      *ssm,
                          FpDevice    *dev,
                          guint8       category,
                          guint8       command,
                          const gchar *what)
{
  g_autoptr(GError) error = NULL;
  const guint8 *pl;
  gsize pl_len;

  if (!goodix_parse_reply_exact (dev, category, command, &pl, &pl_len, &error))
    {
      g_prefix_error (&error, "%s: ", what);
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return FALSE;
    }

  goodix_log_hex (what, pl, pl_len);
  return TRUE;
}

static double
goodix_scan_wait_seconds (FpiDeviceGoodix53x5 *self)
{
  return (g_get_monotonic_time () - self->fdt_wait_start) / (double) G_USEC_PER_SEC;
}

/* Decrypt and decode the frame in the 0xB2 reply to mcu_get_image */
static guint16 *
goodix_scan_decrypt_frame (FpDevice *dev,
                           GError  **error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autofree guint8 *plain = NULL;
  const guint8 *data;
  gsize data_len, plain_len;

  if (!goodix_parse_pack (dev, GOODIX_PACK_FLAGS_TLS_DATA, &data, &data_len,
                          error))
    return NULL;

  /* The prefix has been [00][20][length LE16][00 x5] so far; a TLS 1.2
   * application-data record (0x17 0x03 0x03) must follow it. */
  if (data_len <= GOODIX_IMAGE_TLS_OFFSET + 5 ||
      data[GOODIX_IMAGE_TLS_OFFSET] != 0x17 ||
      data[GOODIX_IMAGE_TLS_OFFSET + 1] != 0x03 ||
      data[GOODIX_IMAGE_TLS_OFFSET + 2] != 0x03)
    {
      goodix_log_hex ("Image pack prefix", data,
                      MIN (data_len, GOODIX_IMAGE_TLS_OFFSET + 5));
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "No TLS application-data record at offset %d of image pack",
                   GOODIX_IMAGE_TLS_OFFSET);
      return NULL;
    }

  if (!goodix_tls_decrypt (self->tls, data + GOODIX_IMAGE_TLS_OFFSET,
                           data_len - GOODIX_IMAGE_TLS_OFFSET,
                           &plain, &plain_len, error))
    return NULL;

  /* driver_5503.py reads 7684 plaintext bytes and drops the last 4 */
  if (plain_len != GOODIX_SENSOR_RAW12_BYTES + 4)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected decrypted image size: %zu", plain_len);
      return NULL;
    }

  return goodix_device_decode_image (plain, GOODIX_SENSOR_RAW12_BYTES);
}

/* Log frame statistics and, if GOODIX5503_DUMP_DIR is set, save the frame
 * as <kind>-<seq>.pgm. Saving is diagnostic only and never fails the scan. */
static void
goodix_scan_report_frame (const gchar   *kind,
                          guint          seq,
                          const guint16 *img12)
{
  const gchar *dump_dir = g_getenv (GOODIX_DUMP_DIR_ENV);
  guint16 min = G_MAXUINT16, max = 0;
  guint64 sum = 0;

  for (gsize i = 0; i < GOODIX_SENSOR_PIXELS; i++)
    {
      min = MIN (min, img12[i]);
      max = MAX (max, img12[i]);
      sum += img12[i];
    }

  fp_info ("Captured %s frame %u: min %u max %u mean %" G_GUINT64_FORMAT,
           kind, seq, min, max, sum / GOODIX_SENSOR_PIXELS);

  if (dump_dir)
    {
      g_autoptr(GError) error = NULL;
      g_autofree gchar *name = g_strdup_printf ("%s-%u.pgm", kind, seq);
      g_autofree gchar *path = g_build_filename (dump_dir, name, NULL);

      if (goodix_device_write_pgm (img12, path, &error))
        fp_info ("Saved %s", path);
      else
        fp_warn ("Failed to save %s: %s", path, error->message);
    }
}

/* ========================================================================
 * FDT zone polling
 * ======================================================================== */

static void
goodix_scan_poll_zones (FpiSsm   *ssm,
                        FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->fdt_poll_start = g_get_monotonic_time ();
  goodix_cmd_mcu_switch_to_fdt_mode (ssm, dev, fdt_mode_clear,
                                     sizeof (fdt_mode_clear));
}

/* Zone readings from the fdt_mode reply:
 * [hdr(2)][zone mask LE16][six zone readings LE16] */
static gboolean
goodix_scan_read_zones (FpiSsm   *ssm,
                        FpDevice *dev,
                        guint16  *zones)
{
  g_autoptr(GError) error = NULL;
  const guint8 *pl;
  gsize pl_len;

  if (!goodix_parse_reply_exact (dev, 0x3, 0x3, &pl, &pl_len, &error))
    {
      g_prefix_error (&error, "FDT poll: ");
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return FALSE;
    }

  if (pl_len < 4 + 2 * GOODIX_FDT_ZONES)
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "FDT poll reply too short: %zu",
                                                     pl_len));
      return FALSE;
    }

  for (int i = 0; i < GOODIX_FDT_ZONES; i++)
    zones[i] = pl[4 + 2 * i] | ((guint16) pl[5 + 2 * i] << 8);

  return TRUE;
}

/* How far each zone sits below the no-finger baseline */
static void
goodix_scan_zone_drops (FpiDeviceGoodix53x5 *self,
                        const guint16       *zones,
                        gint                *drops)
{
  for (int i = 0; i < GOODIX_FDT_ZONES; i++)
    drops[i] = (gint) self->fdt_baseline[i] - (gint) zones[i];
}

static void
goodix_scan_log_poll (FpiDeviceGoodix53x5 *self,
                      const gchar         *wait,
                      const guint16       *zones,
                      const gint          *drops)
{
  if (!self->fdt_debug)
    return;

  fp_info ("FDT-POLL %s t=+%5.2f zones=%3u %3u %3u %3u %3u %3u "
           "drop=%4d %4d %4d %4d %4d %4d consecutive=%u",
           wait, goodix_scan_wait_seconds (self),
           zones[0], zones[1], zones[2], zones[3], zones[4], zones[5],
           drops[0], drops[1], drops[2], drops[3], drops[4], drops[5],
           self->fdt_consecutive);
}

/* Poll again GOODIX_FDT_POLL_PERIOD ms after the previous poll started.
 * The delay is a GLib timeout, so nothing blocks while waiting. */
static void
goodix_scan_schedule_poll (FpiSsm              *ssm,
                           FpiDeviceGoodix53x5 *self,
                           int                  poll_state)
{
  gint64 elapsed_ms = (g_get_monotonic_time () - self->fdt_poll_start) / 1000;

  if (elapsed_ms >= GOODIX_FDT_POLL_PERIOD)
    fpi_ssm_jump_to_state (ssm, poll_state);
  else
    fpi_ssm_jump_to_state_delayed (ssm, poll_state,
                                   GOODIX_FDT_POLL_PERIOD - elapsed_ms);
}

/* libfprint cancels the action through self->cancel; polls check it before
 * each round so a wait ends within one poll period. */
static gboolean
goodix_scan_wait_cancelled (FpiSsm              *ssm,
                            FpiDeviceGoodix53x5 *self)
{
  if (self->cancel == NULL || !g_cancellable_is_cancelled (self->cancel))
    return FALSE;

  fpi_ssm_mark_failed (ssm,
                       g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                            "Finger wait cancelled"));
  return TRUE;
}

/* Forward declarations for the SSM handlers below */
static void goodix_ref_capture_ssm_handler (FpiSsm *ssm, FpDevice *dev);
static void goodix_finger_wait_ssm_handler (FpiSsm *ssm, FpDevice *dev);
static void goodix_capture_ssm_handler (FpiSsm *ssm, FpDevice *dev);
static void goodix_finger_up_ssm_handler (FpiSsm *ssm, FpDevice *dev);
static void goodix_deactivate_ssm_handler (FpiSsm *ssm, FpDevice *dev);

/* ========================================================================
 * No-finger reference capture SSM ("clear" frame in driver_5503.py)
 * ======================================================================== */

static void
goodix_ref_capture_ssm_handler (FpiSsm   *ssm,
                                FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_REF_CAPTURE_FDT_MODE:
      goodix_cmd_mcu_switch_to_fdt_mode (ssm, dev, fdt_mode_clear,
                                         sizeof (fdt_mode_clear));
      break;

    case GOODIX_REF_CAPTURE_GET_IMAGE:
      if (!goodix_scan_expect_reply (ssm, dev, 0x3, 0x3, "FDT mode reply"))
        return;

      goodix_cmd_mcu_get_image (ssm, dev, get_image_request,
                                sizeof (get_image_request));
      break;

    case GOODIX_REF_CAPTURE_DECODE:
      {
        g_autoptr(GError) error = NULL;
        guint16 *img12 = goodix_scan_decrypt_frame (dev, &error);

        if (img12 == NULL)
          {
            g_prefix_error (&error, "Reference frame: ");
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        goodix_scan_report_frame ("clear", self->dump_seq, img12);

        g_clear_pointer (&self->reference_image, g_free);
        self->reference_image = img12;
        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

/* ========================================================================
 * Finger-wait SSM (polling for finger down)
 * ======================================================================== */

static void
goodix_finger_wait_ssm_handler (FpiSsm   *ssm,
                                FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_FINGER_WAIT_START:
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_PRESENT);
      self->fdt_debug = g_strcmp0 (g_getenv (GOODIX_FDT_DEBUG_ENV), "1") == 0;
      self->fdt_have_baseline = FALSE;
      self->fdt_consecutive = 0;
      self->fdt_rise_consecutive = 0;
      self->fdt_wait_start = g_get_monotonic_time ();
      fp_info ("Waiting for finger down");
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_FINGER_WAIT_POLL:
      if (goodix_scan_wait_cancelled (ssm, self))
        return;

      goodix_scan_poll_zones (ssm, dev);
      break;

    case GOODIX_FINGER_WAIT_EVAL:
      {
        guint16 zones[GOODIX_FDT_ZONES];
        gint drops[GOODIX_FDT_ZONES];
        gint max_drop = G_MININT, max_rise = G_MININT;

        if (!goodix_scan_read_zones (ssm, dev, zones))
          return;

        /* The first reading of the wait is the no-finger baseline; the
         * finger-up wait of this scan compares against it too. */
        if (!self->fdt_have_baseline)
          {
            memcpy (self->fdt_baseline, zones, sizeof (zones));
            self->fdt_have_baseline = TRUE;
            fp_info ("FDT baseline: %u %u %u %u %u %u",
                     zones[0], zones[1], zones[2], zones[3], zones[4], zones[5]);
            goodix_scan_schedule_poll (ssm, self, GOODIX_FINGER_WAIT_POLL);
            return;
          }

        goodix_scan_zone_drops (self, zones, drops);
        for (int i = 0; i < GOODIX_FDT_ZONES; i++)
          {
            max_drop = MAX (max_drop, drops[i]);
            max_rise = MAX (max_rise, -drops[i]);
          }

        /* A finger already on the sensor when the wait started (e.g. a quick
         * re-touch) ended up in the baseline and the reference frame. Once
         * it lifts, the readings rise above that baseline and a new touch
         * would never be detected: retake the reference and the baseline. */
        if (max_rise >= GOODIX_FDT_DOWN_DROP)
          self->fdt_rise_consecutive++;
        else
          self->fdt_rise_consecutive = 0;

        if (max_drop >= GOODIX_FDT_DOWN_DROP)
          self->fdt_consecutive++;
        else
          self->fdt_consecutive = 0;

        goodix_scan_log_poll (self, "down", zones, drops);

        if (self->fdt_rise_consecutive >= GOODIX_FDT_CONSECUTIVE)
          {
            fp_info ("Finger was on the sensor when the wait started (zone rise %d), "
                     "retaking the no-finger reference", max_rise);
            fpi_ssm_jump_to_state (ssm, GOODIX_FINGER_WAIT_RECAPTURE_REF);
            return;
          }

        if (self->fdt_consecutive < GOODIX_FDT_CONSECUTIVE)
          {
            goodix_scan_schedule_poll (ssm, self, GOODIX_FINGER_WAIT_POLL);
            return;
          }

        fp_info ("Finger down detected after %.1f s (largest zone drop %d)",
                 goodix_scan_wait_seconds (self), max_drop);
        fpi_device_report_finger_status_changes (dev,
                                                 FP_FINGER_STATUS_PRESENT,
                                                 FP_FINGER_STATUS_NEEDED);
        fpi_ssm_mark_completed (ssm);
      }
      break;

    case GOODIX_FINGER_WAIT_RECAPTURE_REF:
      goodix_scan_start_ref_capture_subsm (ssm, dev);
      break;

    case GOODIX_FINGER_WAIT_RECAPTURE_DONE:
      self->fdt_have_baseline = FALSE;
      self->fdt_consecutive = 0;
      self->fdt_rise_consecutive = 0;
      fpi_ssm_jump_to_state (ssm, GOODIX_FINGER_WAIT_POLL);
      break;
    }
}

/* ========================================================================
 * Capture SSM
 * ======================================================================== */

static void
goodix_capture_ssm_handler (FpiSsm   *ssm,
                            FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_CAPTURE_GET_IMAGE:
      goodix_cmd_mcu_get_image (ssm, dev, get_image_request,
                                sizeof (get_image_request));
      break;

    case GOODIX_CAPTURE_DECODE:
      {
        g_autoptr(GError) error = NULL;
        g_autofree guint16 *img12 = goodix_scan_decrypt_frame (dev, &error);

        if (img12 == NULL)
          {
            g_prefix_error (&error, "Finger frame: ");
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        goodix_scan_report_frame ("finger", self->dump_seq++, img12);

        if (self->reference_image == NULL)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Missing reference image"));
            return;
          }

        /* Store the reference-subtracted 8-bit frame for SIGFM matching */
        g_free (self->captured_image);
        self->captured_image = goodix_device_image_to_8bit (img12,
                                                            self->reference_image);
        self->captured_clipped_fraction =
          goodix_device_image_clipped_fraction (img12);
        g_clear_pointer (&self->reference_image, g_free);

        fpi_ssm_mark_completed (ssm);
      }
      break;
    }
}

/* ========================================================================
 * Finger-up SSM
 * ======================================================================== */

static void
goodix_finger_up_ssm_handler (FpiSsm   *ssm,
                              FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_FINGER_UP_START:
      /* Lift-off is a return to the no-finger baseline of this scan; a
       * reading taken now would include the finger. */
      if (!self->fdt_have_baseline)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "No FDT baseline for finger-up wait"));
          return;
        }

      self->fdt_consecutive = 0;
      self->fdt_wait_start = g_get_monotonic_time ();
      fp_info ("Waiting for finger up");
      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_FINGER_UP_POLL:
      if (goodix_scan_wait_cancelled (ssm, self))
        return;

      goodix_scan_poll_zones (ssm, dev);
      break;

    case GOODIX_FINGER_UP_EVAL:
      {
        guint16 zones[GOODIX_FDT_ZONES];
        gint drops[GOODIX_FDT_ZONES];
        gboolean at_baseline = TRUE;

        if (!goodix_scan_read_zones (ssm, dev, zones))
          return;

        goodix_scan_zone_drops (self, zones, drops);
        for (int i = 0; i < GOODIX_FDT_ZONES; i++)
          if (abs (drops[i]) > GOODIX_FDT_UP_MARGIN)
            at_baseline = FALSE;

        if (at_baseline)
          self->fdt_consecutive++;
        else
          self->fdt_consecutive = 0;

        goodix_scan_log_poll (self, "up", zones, drops);

        if (self->fdt_consecutive < GOODIX_FDT_CONSECUTIVE)
          {
            goodix_scan_schedule_poll (ssm, self, GOODIX_FINGER_UP_POLL);
            return;
          }

        fp_info ("Finger up detected after %.1f s",
                 goodix_scan_wait_seconds (self));
        fpi_device_report_finger_status_changes (dev,
                                                 FP_FINGER_STATUS_NONE,
                                                 FP_FINGER_STATUS_PRESENT | FP_FINGER_STATUS_NEEDED);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_FINGER_UP_IDLE_ARM:
      goodix_cmd_mcu_switch_to_fdt_down (ssm, dev, fdt_down_idle,
                                         sizeof (fdt_down_idle));
      break;

    case GOODIX_FINGER_UP_IDLE_ARM_REPLY:
      /* Consume the immediate 0x32 so it doesn't land where the MCU state
       * reply is expected */
      goodix_recv_start_optional (ssm, dev, GOODIX_FDT_ARM_REPLY_TIMEOUT);
      break;

    case GOODIX_FINGER_UP_QUERY_MCU_STATE:
      if (goodix_rx_has_message (dev) &&
          !goodix_scan_expect_reply (ssm, dev, 0x3, 0x1, "Idle arm reply"))
        return;

      goodix_cmd_query_mcu_state (ssm, dev, query_mcu_state_idle,
                                  sizeof (query_mcu_state_idle));
      break;

    case GOODIX_FINGER_UP_DONE:
      if (!goodix_scan_expect_reply (ssm, dev, 0xA, 0x7, "MCU state"))
        return;

      fpi_ssm_mark_completed (ssm);
      break;
    }
}

/* ========================================================================
 * Deactivate SSM
 * ======================================================================== */

static void
goodix_deactivate_ssm_handler (FpiSsm   *ssm,
                               FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_DEACTIVATE_FDT_MODE:
      goodix_cmd_mcu_switch_to_fdt_mode (ssm, dev, fdt_mode_down,
                                         sizeof (fdt_mode_down));
      break;

    case GOODIX_DEACTIVATE_IDLE_ARM:
      if (!goodix_scan_expect_reply (ssm, dev, 0x3, 0x3, "FDT mode reply"))
        return;

      goodix_cmd_mcu_switch_to_fdt_down (ssm, dev, fdt_down_idle,
                                         sizeof (fdt_down_idle));
      break;

    case GOODIX_DEACTIVATE_IDLE_ARM_REPLY:
      goodix_recv_start_optional (ssm, dev, GOODIX_FDT_ARM_REPLY_TIMEOUT);
      break;

    case GOODIX_DEACTIVATE_QUERY_MCU_STATE:
      if (goodix_rx_has_message (dev) &&
          !goodix_scan_expect_reply (ssm, dev, 0x3, 0x1, "Idle arm reply"))
        return;

      goodix_cmd_query_mcu_state (ssm, dev, query_mcu_state_idle,
                                  sizeof (query_mcu_state_idle));
      break;

    case GOODIX_DEACTIVATE_DONE:
      if (!goodix_scan_expect_reply (ssm, dev, 0xA, 0x7, "MCU state"))
        return;

      fpi_ssm_mark_completed (ssm);
      break;
    }
}

/* ========================================================================
 * Sub-SSM start wrappers
 * ======================================================================== */

void
goodix_scan_start_ref_capture_subsm (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiSsm *sub = fpi_ssm_new (dev, goodix_ref_capture_ssm_handler,
                             GOODIX_REF_CAPTURE_NUM_STATES);

  fpi_ssm_start_subsm (parent_ssm, sub);
}

void
goodix_scan_start_finger_wait_subsm (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiSsm *sub = fpi_ssm_new (dev, goodix_finger_wait_ssm_handler,
                             GOODIX_FINGER_WAIT_NUM_STATES);

  fpi_ssm_start_subsm (parent_ssm, sub);
}

void
goodix_scan_start_capture_subsm (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiSsm *sub = fpi_ssm_new (dev, goodix_capture_ssm_handler,
                             GOODIX_CAPTURE_NUM_STATES);

  fpi_ssm_start_subsm (parent_ssm, sub);
}

void
goodix_scan_start_finger_up_subsm (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiSsm *sub = fpi_ssm_new (dev, goodix_finger_up_ssm_handler,
                             GOODIX_FINGER_UP_NUM_STATES);

  fpi_ssm_start_subsm (parent_ssm, sub);
}

void
goodix_scan_start_deactivate_subsm (FpiSsm *parent_ssm, FpDevice *dev)
{
  FpiSsm *sub = fpi_ssm_new (dev, goodix_deactivate_ssm_handler,
                             GOODIX_DEACTIVATE_NUM_STATES);

  fpi_ssm_start_subsm (parent_ssm, sub);
}
