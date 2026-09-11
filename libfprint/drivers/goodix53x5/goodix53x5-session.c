/*
 * Goodix 53x5 driver for libfprint — Device session (open, GTLS, reinit)
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
#include "goodix53x5-calibration.h"
#include "goodix53x5-image.h"
#include "goodix53x5-session.h"

#include <string.h>


/* Open SSM — full device initialization */
typedef enum {
  GOODIX_OPEN_USB_RESET = 0,
  GOODIX_OPEN_CLAIM_INTERFACE,
  GOODIX_OPEN_DRAIN,
  GOODIX_OPEN_PING,
  GOODIX_OPEN_READ_FW_VERSION,
  GOODIX_OPEN_RESET,
  GOODIX_OPEN_READ_CHIP_ID,
  GOODIX_OPEN_READ_OTP,
  GOODIX_OPEN_PARSE_OTP,
  GOODIX_OPEN_READ_PSK_HASH,
  GOODIX_OPEN_WRITE_PSK,
  GOODIX_OPEN_VERIFY_PSK_WRITE,
  GOODIX_OPEN_CHECK_PSK_WRITE,
  GOODIX_OPEN_TLS_REQUEST,
  GOODIX_OPEN_TLS_RECV,
  GOODIX_OPEN_TLS_FEED,
  GOODIX_OPEN_TLS_SENT,
  GOODIX_OPEN_TLS_COMPLETE,
  GOODIX_OPEN_UPLOAD_CONFIG,
  GOODIX_OPEN_SET_DRV_STATE_1,
  GOODIX_OPEN_SET_DRV_STATE_2,
  GOODIX_OPEN_POV_IMAGE,
  GOODIX_OPEN_POV_IMAGE_DONE,
  GOODIX_OPEN_NUM_STATES,
} GoodixOpenState;


/* All-zero PSK */
static const guint8 goodix_psk[GOODIX_PSK_LEN] = { 0 };

/* PMK hash expected for 5503 (from driver_5503.py) */
static const guint8 goodix_pmk_hash[GOODIX_PMK_HASH_LEN] = {
  0x81, 0xb8, 0xff, 0x49, 0x06, 0x12, 0x02, 0x2a,
  0x12, 0x1a, 0x94, 0x49, 0xee, 0x3a, 0xad, 0x27,
  0x92, 0xf3, 0x2b, 0x9f, 0x31, 0x41, 0x18, 0x2c,
  0xd0, 0x10, 0x19, 0x94, 0x5e, 0xe5, 0x03, 0x61,
};

/* PSK white box for writing all-zero PSK */
static const guint8 goodix_psk_white_box[GOODIX_PSK_WHITE_BOX_LEN] = {
  0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f,
  0x12, 0xc4, 0x75, 0x1f, 0x1e, 0x5c, 0x2c, 0xc0,
  0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
  0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b,
  0x6f, 0xd6, 0x6b, 0x1d, 0x97, 0xcf, 0x80, 0xf1,
  0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
  0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75,
  0xc4, 0x1e, 0x65, 0x92, 0xcd, 0x2a, 0x2f, 0x9e,
  0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
  0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3,
  0x1e, 0xdb, 0x33, 0x94, 0x04, 0x6e, 0xc0, 0x6b,
  0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5,
};

/* ========================================================================
 * Open SSM — full device initialization
 * ======================================================================== */

#define GOODIX_ALLOW_PSK_WRITE_ENV "GOODIX5503_ALLOW_PSK_WRITE"
/* TRUE if the device reports the hash of our all-zero PSK: PMK_HASH from
 * driver_5503.py, or the plain SHA256 of the PSK. */
static gboolean
goodix_psk_hash_matches (const guint8 *hash,
                         gsize         hash_len)
{
  g_autoptr(GChecksum) sha = g_checksum_new (G_CHECKSUM_SHA256);
  guint8 sha_hash[32];
  gsize sha_len = sizeof (sha_hash);

  if (hash_len < GOODIX_PMK_HASH_LEN)
    return FALSE;

  if (memcmp (hash, goodix_pmk_hash, GOODIX_PMK_HASH_LEN) == 0)
    return TRUE;

  g_checksum_update (sha, goodix_psk, GOODIX_PSK_LEN);
  g_checksum_get_digest (sha, sha_hash, &sha_len);

  return memcmp (hash, sha_hash, sizeof (sha_hash)) == 0;
}

/* Writing the PSK is persistent on the sensor and clobbers the PSK that the
 * Windows driver provisions on dual-boot machines, so it is opt-in. */
static gboolean
goodix_psk_write_allowed (void)
{
  return g_strcmp0 (g_getenv (GOODIX_ALLOW_PSK_WRITE_ENV), "1") == 0;
}

static void
goodix_open_ssm_handler (FpiSsm   *ssm,
                         FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixOpenState state = fpi_ssm_get_cur_state (ssm);

  switch (state)
    {
    case GOODIX_OPEN_USB_RESET:
      {
        GError *error = NULL;
        fp_dbg ("Setting USB configuration");
        if (!g_usb_device_set_configuration (
                fpi_device_get_usb_device (dev), 1, &error))
          {
            fp_warn ("GOODIX_OPEN_SSM: set_configuration failed: %s",
                     error ? error->message : "none");
            g_clear_error (&error);
          }
      }
      fpi_ssm_next_state (ssm);
      break;
    case GOODIX_OPEN_CLAIM_INTERFACE:
      {
        GError *error = NULL;
        fp_dbg ("Claiming interface %d", GOODIX_USB_INTERFACE);
        if (!g_usb_device_claim_interface (
                fpi_device_get_usb_device (dev), GOODIX_USB_INTERFACE,
                G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, &error))
          {
            fp_warn ("GOODIX_OPEN_SSM: claim_interface %d failed: %s",
                     GOODIX_USB_INTERFACE, error ? error->message : "none");
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        self->usb_interface_claimed = TRUE;
        fp_dbg ("Interface %d claimed", GOODIX_USB_INTERFACE);
        fpi_ssm_next_state (ssm);
      }
      break;
    case GOODIX_OPEN_DRAIN:
      /* goodix.py empty_buffer(): discard replies left over from a previous
       * session (or from Windows) before the first command. */
      goodix_drain_start (ssm, dev);
      break;
    case GOODIX_OPEN_PING:
      goodix_cmd_ping (ssm, dev);
      break;

    case GOODIX_OPEN_READ_FW_VERSION:
      goodix_cmd_read_fw_version (ssm, dev);
      break;

    case GOODIX_OPEN_RESET:
      {
        /* Parse the firmware version reply before sending the reset */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_fw_version_reply (dev, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        g_clear_pointer (&self->fw_version, g_free);
        self->fw_version = g_strndup ((const gchar *) pl,
                                      strnlen ((const gchar *) pl, pl_len));
        fp_info ("Firmware version: %s", self->fw_version);

        goodix_cmd_reset_sensor (ssm, dev);
      }
      break;

    case GOODIX_OPEN_READ_CHIP_ID:
      {
        /* Check the reset reply ([status][number LE16]) before reading the
         * chip ID */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_parse_reply_exact (dev, 0xA, 0x1, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        if (pl_len < 1 || pl[0] != 0x01)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Sensor reset failed"));
            return;
          }

        goodix_cmd_read_chip_id (ssm, dev);
      }
      break;

    case GOODIX_OPEN_READ_OTP:
      {
        /* Parse the chip ID reply before reading the OTP */
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;
        guint32 chip_id;

        if (!goodix_cmd_parse_chip_id_reply (dev, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        if (pl_len < 4)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Unexpected chip ID reply length: %zu",
                                                           pl_len));
            return;
          }

        chip_id = goodix_crypto_decode_u32 (pl);
        fp_info ("Chip ID: 0x%08x", chip_id);

        goodix_cmd_read_otp (ssm, dev);
      }
      break;

    case GOODIX_OPEN_PARSE_OTP:
      {
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_otp_reply (dev, &pl, &pl_len, NULL))
          {
            fpi_ssm_mark_failed (ssm,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Failed to parse OTP response"));
            return;
          }

        g_clear_pointer (&self->otp_data, g_free);
        self->otp_data = g_memdup2 (pl, pl_len);
        self->otp_len = pl_len;
        goodix_log_hex ("OTP", pl, pl_len);

        /* TODO: the 5503 OTP layout is not mapped yet (driver_5503.py only
         * reads it), so skip the 53x5 hash check and calibration parsing. */
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_READ_PSK_HASH:
      /* read_psk_hash via production_read(GOODIX_PSK_READ_FLAGS) */
      goodix_cmd_production_read (ssm, dev, GOODIX_PSK_READ_FLAGS);
      break;

    case GOODIX_OPEN_WRITE_PSK:
      {
        /* Check if PSK hash matches expected PMK hash or all-zero SHA256.
         * Parse the production_read response. */
        const guint8 *psk_data;
        gsize psk_data_len;

        if (!goodix_cmd_parse_production_read_reply (dev, GOODIX_PSK_READ_FLAGS,
                                                     &psk_data, &psk_data_len))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to read PSK hash"));
            return;
          }

        self->psk_write_verify_pending = FALSE;
        self->psk_mismatch = FALSE;

        if (goodix_psk_hash_matches (psk_data, psk_data_len))
          {
            fp_dbg ("PSK hash matches, no need to write");
            fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_TLS_REQUEST);
            return;
          }

        goodix_log_hex ("Device PSK hash", psk_data, psk_data_len);

        if (!goodix_psk_write_allowed ())
          {
            /* Continue without touching the sensor; the TLS handshake will
             * fail later if the device PSK is not the all-zero one. */
            fp_warn ("PSK mismatch, write skipped - set %s=1 to write it",
                     GOODIX_ALLOW_PSK_WRITE_ENV);
            self->psk_mismatch = TRUE;
            fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_TLS_REQUEST);
            return;
          }

        fp_warn ("PSK mismatch and %s=1: writing PSK white box",
                 GOODIX_ALLOW_PSK_WRITE_ENV);
        self->psk_write_verify_pending = TRUE;
        goodix_cmd_production_write (ssm, dev, GOODIX_PSK_WRITE_FLAGS,
                                     goodix_psk_white_box,
                                     GOODIX_PSK_WHITE_BOX_LEN);
      }
      break;

    case GOODIX_OPEN_VERIFY_PSK_WRITE:
      {
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_cmd_parse_production_write_reply (dev,
                                                      GOODIX_PSK_WRITE_FLAGS,
                                                      &pl, &pl_len) ||
            pl_len < 1)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Failed to parse PSK write reply"));
            return;
          }

        if (pl[0] != 0)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "PSK write failed: %u",
                                                           pl[0]));
            return;
          }

        /* Re-read the PSK hash to verify the write before GTLS */
        goodix_cmd_production_read (ssm, dev, GOODIX_PSK_READ_FLAGS);
      }
      break;

    case GOODIX_OPEN_CHECK_PSK_WRITE:
      {
        if (self->psk_write_verify_pending)
          {
            /* Parse the PSK hash re-read after the write */
            const guint8 *psk_data;
            gsize psk_data_len;

            if (!goodix_cmd_parse_production_read_reply (dev, GOODIX_PSK_READ_FLAGS,
                                                         &psk_data,
                                                         &psk_data_len))
              {
                fpi_ssm_mark_failed (ssm,
                                     fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                               "Failed to re-read PSK hash"));
                return;
              }

            if (!goodix_psk_hash_matches (psk_data, psk_data_len))
              {
                fpi_ssm_mark_failed (ssm,
                                     fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                               "PSK hash mismatch after write"));
                return;
              }

            self->psk_write_verify_pending = FALSE;
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    /* TLS-PSK handshake with the sensor as client, as in tool.connect_device()
     * from goodix-fp-dump: records travel in 0xB0 packs without ACKs. */
    case GOODIX_OPEN_TLS_REQUEST:
      {
        g_autoptr(GError) error = NULL;

        g_clear_pointer (&self->tls, goodix_tls_free);
        self->tls = goodix_tls_new (goodix_psk, GOODIX_PSK_LEN, &error);
        if (!self->tls)
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        fp_dbg ("TLS: requesting TLS connection from sensor");
        goodix_cmd_request_tls_connection (ssm, dev);
      }
      break;

    case GOODIX_OPEN_TLS_RECV:
      /* Next flight of TLS records from the sensor */
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;

    case GOODIX_OPEN_TLS_FEED:
      {
        g_autoptr(GError) error = NULL;
        g_autofree guint8 *out = NULL;
        const guint8 *in;
        gsize in_len, out_len;

        if (!goodix_parse_pack (dev, GOODIX_PACK_FLAGS_TLS, &in, &in_len,
                                &error) ||
            !goodix_tls_handshake_step (self->tls, in, in_len, &out, &out_len,
                                        &error))
          {
            if (self->psk_mismatch)
              g_prefix_error (&error,
                              "Device PSK does not match (set %s=1 to write it): ",
                              GOODIX_ALLOW_PSK_WRITE_ENV);
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        if (out_len > 0)
          {
            /* GOODIX_OPEN_TLS_SENT decides whether more records follow */
            goodix_send_pack (ssm, dev, GOODIX_PACK_FLAGS_TLS, out, out_len);
            return;
          }

        if (goodix_tls_handshake_done (self->tls))
          fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_TLS_COMPLETE);
        else
          fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_TLS_RECV);
      }
      break;

    case GOODIX_OPEN_TLS_SENT:
      /* tool.connect_device() sleeps 10 ms after the last flight, otherwise
       * the next USB command times out */
      if (goodix_tls_handshake_done (self->tls))
        fpi_ssm_jump_to_state_delayed (ssm, GOODIX_OPEN_TLS_COMPLETE, 10);
      else
        fpi_ssm_jump_to_state (ssm, GOODIX_OPEN_TLS_RECV);
      break;

    case GOODIX_OPEN_TLS_COMPLETE:
      fp_dbg ("TLS handshake complete: %s, %s",
              goodix_tls_get_version (self->tls),
              goodix_tls_get_cipher (self->tls));

      fpi_ssm_next_state (ssm);
      break;

    case GOODIX_OPEN_UPLOAD_CONFIG:
      {
        gsize cfg_len;
        const guint8 *cfg = goodix_device_get_default_config (&cfg_len);

        self->open_fdt_retries = 0;

        /* driver_5503.py uploads DEVICE_CONFIG verbatim; the 53x5 OTP
         * calibration patching does not apply to the 5503 */
        goodix_cmd_upload_config (ssm, dev, cfg, cfg_len);
      }
      break;

    case GOODIX_OPEN_SET_DRV_STATE_1:
      {
        /* Validate the config upload reply before setting drv state */
        if (!goodix_cmd_parse_config_reply (dev))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Config upload failed"));
            return;
          }

        goodix_cmd_set_drv_state (ssm, dev);
      }
      break;

    case GOODIX_OPEN_SET_DRV_STATE_2:
      /* Windows driver and driver_5503.py call set_drv_state twice */
      goodix_cmd_set_drv_state (ssm, dev);
      break;

    case GOODIX_OPEN_POV_IMAGE:
      goodix_cmd_mcu_get_pov_image (ssm, dev);
      break;

    case GOODIX_OPEN_POV_IMAGE_DONE:
      {
        g_autoptr(GError) error = NULL;
        const guint8 *pl;
        gsize pl_len;

        if (!goodix_parse_reply_exact (dev, 0xD, 0x1, &pl, &pl_len, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        if (pl_len < 1)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "Empty POV image reply"));
            return;
          }

        fp_dbg ("POV image state: 0x%02x", pl[0]);
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_OPEN_NUM_STATES:
      g_assert_not_reached ();
      break;
    }
}

static void
goodix_cleanup_failed_open (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  g_autoptr(GError) cleanup_error = NULL;

  g_clear_pointer (&self->tls, goodix_tls_free);

  if (self->usb_interface_claimed)
    {
      if (!g_usb_device_release_interface (usb_dev, GOODIX_USB_INTERFACE, 0,
                                           &cleanup_error))
        fp_warn ("Failed to release USB interface after open failure: %s",
                 cleanup_error->message);

      self->usb_interface_claimed = FALSE;
      g_clear_error (&cleanup_error);
    }

  if (!g_usb_device_close (usb_dev, &cleanup_error))
    fp_warn ("Failed to close USB device after open failure: %s",
             cleanup_error->message);
}

static void
goodix_open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  self->task_ssm = NULL;

  /* Clean up temp data */
  g_clear_pointer (&self->fdt_data_tx_on, g_free);

  if (error)
    {
      fp_warn ("Device open failed: %s", error->message);

      goodix_cleanup_failed_open (dev);
      fpi_device_open_complete (dev, error);
      return;
    }

  fp_info ("Device initialization complete");
  self->needs_reinit = FALSE;
  fpi_device_open_complete (dev, NULL);
}

void
goodix_start_open_ssm (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, goodix_open_ssm_handler,
                      GOODIX_OPEN_NUM_STATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, goodix_open_ssm_done);
}

/* ========================================================================
 * Post-sleep reinitialization
 * ======================================================================== */

/**
 * If the device needs reinitialization (system sleep happened while it was
 * open), release any stale interface claim and run the full open-time
 * initialization SSM as a sub-SSM of @ssm. The full sequence is required:
 * after an S4 reset/re-enumeration the kernel rebinds cdc_acm to our
 * interface, so recovery needs the same USB reset + claim-with-detach +
 * GTLS handshake as a fresh open.
 *
 * Returns TRUE if a reinit sub-SSM was started (caller returns and the
 * parent advances when it completes), FALSE if no reinit was needed.
 */
gboolean
goodix_maybe_start_reinit_subsm (FpiSsm   *ssm,
                                 FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *sub;

  if (!self->needs_reinit)
    return FALSE;

  fp_info ("Reinitializing device after system sleep");

  if (self->usb_interface_claimed)
    {
      g_autoptr(GError) release_error = NULL;

      /* This is expected to fail with EINVAL after an S4 reset because the
       * kernel already dropped the claim; recovery proceeds either way. */
      if (!g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                           GOODIX_USB_INTERFACE,
                                           0, &release_error))
        fp_dbg ("Releasing stale USB interface before reinit failed "
                "(expected after S4 reset): %s", release_error->message);

      self->usb_interface_claimed = FALSE;
    }

  sub = fpi_ssm_new (dev, goodix_open_ssm_handler,
                     GOODIX_OPEN_NUM_STATES);
  fpi_ssm_start_subsm (ssm, sub);
  return TRUE;
}

/**
 * TRUE for errors that indicate the USB device/claim is likely stale or
 * gone (e.g. system slept while the device was claimed but idle, so the
 * driver suspend hook never ran). Setting needs_reinit on these makes the
 * next action attempt self-heal with a full reinitialization.
 */
gboolean
goodix_error_indicates_stale_device (const GError *error)
{
  return g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_TIMED_OUT) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_NO_DEVICE) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_NOT_OPEN) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_IO) ||
         g_error_matches (error, G_USB_DEVICE_ERROR,
                          G_USB_DEVICE_ERROR_FAILED);
}

/* ========================================================================
 * Suspend / resume policy
 * ======================================================================== */

void
goodix_session_suspend (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  /* Any system sleep while the device is open may invalidate the USB claim
   * and GTLS session: S4 resets or re-enumerates the device and rebinds the
   * cdc_acm kernel driver to our interface. Force a full reinitialization at
   * the start of the next action regardless of what we were doing when sleep
   * hit. A successfully completed action clears this again. */
  self->needs_reinit = TRUE;

  if (action != FPI_DEVICE_ACTION_VERIFY &&
      action != FPI_DEVICE_ACTION_IDENTIFY)
    {
      fpi_device_suspend_complete (dev,
          fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }

  if (self->blocking_ssm)
    {
      /* Cancel the pending read; suspend_complete called from rx callback */
      self->suspend_pending = TRUE;
      g_cancellable_cancel (self->cancel);
    }
  else
    {
      /* Not in a blocking read (e.g. mid-capture), complete immediately */
      fpi_device_suspend_complete (dev, NULL);
    }
}

void
goodix_session_resume (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  if (action != FPI_DEVICE_ACTION_VERIFY &&
      action != FPI_DEVICE_ACTION_IDENTIFY)
    {
      fpi_device_resume_complete (dev,
          fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }

  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  /* Restart the SSM from the re-arm state (resubmits USB reads). Only
   * reachable if suspend completed successfully mid-capture and the SSM
   * armed a blocking wait before the system actually slept. */
  if (self->blocking_ssm)
    {
      fpi_ssm_jump_to_state (self->blocking_ssm, self->blocking_resume_state);
      self->blocking_ssm = NULL;
    }

  fpi_device_resume_complete (dev, NULL);
}
