/*
 * Goodix 53x5 driver for libfprint — USB transport and command execution
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

#include <string.h>

/* USB endpoints — interface 0, EP 1 OUT, EP 2 IN */
#define GOODIX_EP_OUT (0x01 | FPI_USB_ENDPOINT_OUT)
#define GOODIX_EP_IN  (0x02 | FPI_USB_ENDPOINT_IN)

/* goodix.py pads every write to 64 bytes and sends it as 64-byte transfers */
#define GOODIX_USB_CHUNK_SIZE 64

/* empty_buffer() and nop() in goodix.py read with a 100 ms timeout */
#define GOODIX_DRAIN_TIMEOUT   100
#define GOODIX_DRAIN_MAX_READS 64

/* Hex dumps longer than this are truncated */
#define GOODIX_LOG_HEX_MAX 256

#define GOODIX_PROTO_CATEGORY_FDT     0x03
#define GOODIX_PROTO_CMD_FDT_DOWN     0x01
#define GOODIX_PROTO_CMD_FDT_UP       0x02
#define GOODIX_PROTO_CATEGORY_ACK     0x0B
#define GOODIX_PROTO_CMD_ACK          0x00
#define GOODIX_PROTO_ACK_FLAG_VALID   0x01
#define GOODIX_PROTO_CMD_BYTE(category, command) \
  (((category) << 4) | ((command) << 1))

/* Command sub-SSM */
typedef enum {
  GOODIX_CMD_SEND = 0,
  GOODIX_CMD_RECV_ACK,
  GOODIX_CMD_VALIDATE_ACK,
  GOODIX_CMD_RECV_DATA,
  GOODIX_CMD_NUM_STATES,
} GoodixCmdState;

static gboolean
goodix_validate_ack_for_cmd (FpDevice        *dev,
                             const GoodixCmd *cmd,
                             GError         **error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint8 category, command;
  const guint8 *payload;
  gsize payload_len;
  guint8 expected_cmd_byte = GOODIX_PROTO_CMD_BYTE (cmd->category, cmd->command);

  if (!goodix_proto_rx_parse (&self->rx, &category, &command,
                              &payload, &payload_len))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Failed to parse ACK");
      return FALSE;
    }

  if (category != GOODIX_PROTO_CATEGORY_ACK ||
      command != GOODIX_PROTO_CMD_ACK ||
      payload_len < 2)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected ACK: expected cmd_byte=0x%02x, got cat=0x%02x cmd=0x%02x len=%zu",
                   expected_cmd_byte, category, command, payload_len);
      return FALSE;
    }

  if (payload[0] != expected_cmd_byte ||
      (payload[1] & GOODIX_PROTO_ACK_FLAG_VALID) == 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected ACK: expected cmd_byte=0x%02x, got ack_cmd=0x%02x flags=0x%02x",
                   expected_cmd_byte, payload[0], payload[1]);
      return FALSE;
    }

  return TRUE;
}

/* ========================================================================
 * USB I/O helpers
 * ======================================================================== */

void
goodix_log_hex (const gchar  *prefix,
                const guint8 *data,
                gsize         len)
{
  gsize shown = MIN (len, GOODIX_LOG_HEX_MAX);
  g_autoptr(GString) hex = g_string_sized_new (shown * 2 + 1);

  for (gsize i = 0; i < shown; i++)
    g_string_append_printf (hex, "%02x", data[i]);

  fp_dbg ("%s (%zu bytes): %s%s", prefix, len, hex->str,
          shown < len ? "..." : "");
}

/* A padded message pack being written as consecutive 64-byte transfers */
typedef struct
{
  guint8 *buf;
  gsize   len;
  gsize   offset;
} GoodixTxCtx;

static void
goodix_tx_ctx_free (GoodixTxCtx *ctx)
{
  g_free (ctx->buf);
  g_free (ctx);
}

static void goodix_tx_cb (FpiUsbTransfer *transfer,
                          FpDevice       *dev,
                          gpointer        user_data,
                          GError         *error);

static void
goodix_tx_submit_chunk (FpiSsm      *ssm,
                        FpDevice    *dev,
                        GoodixTxCtx *ctx)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (transfer, GOODIX_EP_OUT,
                                   ctx->buf + ctx->offset,
                                   GOODIX_USB_CHUNK_SIZE, NULL);
  fpi_usb_transfer_submit (transfer, GOODIX_CMD_TIMEOUT, NULL,
                           goodix_tx_cb, ctx);
}

static void
goodix_tx_cb (FpiUsbTransfer *transfer,
              FpDevice       *dev,
              gpointer        user_data,
              GError         *error)
{
  GoodixTxCtx *ctx = user_data;

  if (error)
    {
      fp_warn ("USB TX failed at offset %zu/%zu: %s",
               ctx->offset, ctx->len, error->message);
      goodix_tx_ctx_free (ctx);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  ctx->offset += GOODIX_USB_CHUNK_SIZE;

  if (ctx->offset < ctx->len)
    {
      goodix_tx_submit_chunk (transfer->ssm, dev, ctx);
      return;
    }

  goodix_tx_ctx_free (ctx);
  fpi_ssm_next_state (transfer->ssm);
}

void
goodix_send_pack (FpiSsm       *ssm,
                  FpDevice     *dev,
                  guint8        flags,
                  const guint8 *data,
                  gsize         data_len)
{
  g_autofree guint8 *pack = NULL;
  gsize pack_len;
  GoodixTxCtx *ctx;

  pack = goodix_proto_build_pack (flags, data, data_len, &pack_len);

  goodix_log_hex ("USB TX", pack, pack_len);

  ctx = g_new0 (GoodixTxCtx, 1);
  ctx->len = ((pack_len + GOODIX_USB_CHUNK_SIZE - 1) / GOODIX_USB_CHUNK_SIZE) *
             GOODIX_USB_CHUNK_SIZE;
  ctx->buf = g_malloc0 (ctx->len);
  memcpy (ctx->buf, pack, pack_len);

  goodix_tx_submit_chunk (ssm, dev, ctx);
}

/* Send a protocol message in a 0xA0 pack. Advances the SSM on completion. */
static void
goodix_send_message (FpiSsm   *ssm,
                     FpDevice *dev,
                     guint8    category,
                     guint8    command,
                     const guint8 *payload,
                     gsize     payload_len,
                     gboolean  use_checksum)
{
  g_autofree guint8 *msg = NULL;
  gsize msg_len;

  msg = goodix_proto_build_message (category, command, payload, payload_len,
                                    use_checksum, &msg_len);
  goodix_send_pack (ssm, dev, GOODIX_PACK_FLAGS_PROTOCOL, msg, msg_len);
}

/* Forward declarations */
static void goodix_rx_cb (FpiUsbTransfer *transfer,
                          FpDevice       *dev,
                          gpointer        user_data,
                          GError         *error);

static void goodix_drain_cb (FpiUsbTransfer *transfer,
                             FpDevice       *dev,
                             gpointer        user_data,
                             GError         *error);

static void
goodix_rx_submit (FpiSsm       *ssm,
                  FpDevice     *dev,
                  guint         timeout_ms,
                  GCancellable *cancellable)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, GOODIX_EP_IN, GOODIX_RX_BUF_SIZE);
  fpi_usb_transfer_submit (transfer, timeout_ms, cancellable,
                           goodix_rx_cb, NULL);
}

static void
goodix_recv_start_full (FpiSsm       *ssm,
                        FpDevice     *dev,
                        guint         timeout_ms,
                        GCancellable *cancellable,
                        gboolean      timeout_ok)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  goodix_proto_rx_reset (&self->rx);
  self->rx_timeout = timeout_ms;
  self->rx_cancellable = cancellable;
  self->rx_timeout_ok = timeout_ok;

  goodix_rx_submit (ssm, dev, timeout_ms, cancellable);
}

void
goodix_recv_start (FpiSsm       *ssm,
                   FpDevice     *dev,
                   guint         timeout_ms,
                   GCancellable *cancellable)
{
  goodix_recv_start_full (ssm, dev, timeout_ms, cancellable, FALSE);
}

void
goodix_recv_start_optional (FpiSsm   *ssm,
                            FpDevice *dev,
                            guint     timeout_ms)
{
  goodix_recv_start_full (ssm, dev, timeout_ms, NULL, TRUE);
}

gboolean
goodix_rx_has_message (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  return goodix_proto_rx_complete (&self->rx);
}

static void
goodix_drain_submit (FpiSsm   *ssm,
                     FpDevice *dev,
                     guint     reads)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, GOODIX_EP_IN, GOODIX_RX_BUF_SIZE);
  fpi_usb_transfer_submit (transfer, GOODIX_DRAIN_TIMEOUT, NULL,
                           goodix_drain_cb, GUINT_TO_POINTER (reads));
}

static void
goodix_drain_cb (FpiUsbTransfer *transfer,
                 FpDevice       *dev,
                 gpointer        user_data,
                 GError         *error)
{
  guint reads = GPOINTER_TO_UINT (user_data);

  if (error)
    {
      if (g_error_matches (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_TIMED_OUT))
        {
          fp_dbg ("USB IN endpoint drained (%u stale transfers)", reads);
          g_error_free (error);
          fpi_ssm_next_state (transfer->ssm);
          return;
        }

      fp_warn ("USB RX failed while draining: %s", error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  goodix_log_hex ("USB RX stale", transfer->buffer, transfer->actual_length);

  if (++reads >= GOODIX_DRAIN_MAX_READS)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Device kept sending data while draining"));
      return;
    }

  goodix_drain_submit (transfer->ssm, dev, reads);
}

void
goodix_drain_start (FpiSsm   *ssm,
                    FpDevice *dev)
{
  goodix_drain_submit (ssm, dev, 0);
}

static void
goodix_rx_cb (FpiUsbTransfer *transfer,
              FpDevice       *dev,
              gpointer        user_data,
              GError         *error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (error)
    {
      if (self->rx_timeout_ok && self->rx.len == 0 &&
          g_error_matches (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_TIMED_OUT))
        {
          fp_dbg ("USB RX: no reply within %u ms (optional)", self->rx_timeout);
          g_error_free (error);
          fpi_ssm_next_state (transfer->ssm);
          return;
        }

      if (!self->suspend_pending &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
          self->action_result_reported &&
          !self->verify_wait_finger_up &&
          transfer->ssm == self->blocking_ssm)
        {
          /* Once verify/identify has reported a result, libfprint may cancel
           * the action immediately. Finish the sensor shutdown sequence rather
           * than bailing out and leaving the MCU armed for the next open.
           * The shutdown state was recorded by the scan flow when it armed
           * this blocking read. */
          g_clear_error (&error);
          self->blocking_ssm = NULL;
          fpi_ssm_jump_to_state (transfer->ssm, self->blocking_shutdown_state);
          return;
        }

      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
          self->suspend_pending)
        {
          /* Do not carry an armed FDT wait across system sleep. The USB device
           * may disappear and re-enumerate during S4, leaving fprintd with a
           * stale open device. Abort the active auth so the greeter starts a
           * fresh operation after resume. */
          g_clear_error (&error);
          self->suspend_pending = FALSE;
          self->blocking_ssm = NULL;
          fpi_device_suspend_complete (dev,
              fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
          fpi_ssm_mark_failed (transfer->ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY,
                                                         "Cannot run while suspended."));
          return;
        }

      self->blocking_ssm = NULL;

      if (self->suspend_pending)
        {
          /* Non-cancellation error during suspend — report it and fail SSM */
          self->suspend_pending = FALSE;
          fpi_device_suspend_complete (dev, g_error_copy (error));
        }

      fp_warn ("USB RX failed (timeout %u ms, %zu bytes buffered): %s",
               self->rx_timeout, self->rx.len, error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (self->suspend_pending && transfer->ssm == self->blocking_ssm)
    {
      /* Data (e.g. an FDT touch event) raced with the suspend cancellation
       * and the transfer completed before the cancel took effect. Treat it
       * exactly like the cancelled case above; otherwise the pending suspend
       * request would never be completed and system sleep would block until
       * logind times out. */
      self->suspend_pending = FALSE;
      self->blocking_ssm = NULL;
      fpi_device_suspend_complete (dev,
          fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_BUSY,
                                                     "Cannot run while suspended."));
      return;
    }

  /* Skip zero-length reads — resubmit with same timeout/cancellable */
  if (transfer->actual_length == 0)
    {
      goodix_rx_submit (transfer->ssm, dev, self->rx_timeout,
                        self->rx_cancellable);
      return;
    }

  goodix_log_hex ("USB RX", transfer->buffer, transfer->actual_length);

  if (!goodix_proto_rx_feed_chunk (&self->rx, transfer->buffer,
                                   transfer->actual_length))
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Protocol reassembly error"));
      return;
    }

  if (goodix_proto_rx_complete (&self->rx))
    {
      /* Message complete — advance SSM */
      fpi_ssm_next_state (transfer->ssm);
    }
  else
    {
      /* Need more data — use the stored cancellable for continuations.
       * For finger-wait (timeout=0/infinite), once we start getting data
       * the remaining bytes should arrive quickly, so use DATA_TIMEOUT. */
      goodix_rx_submit (transfer->ssm, dev, GOODIX_DATA_TIMEOUT,
                        self->rx_cancellable);
    }
}

void
goodix_recv_start_cancellable (FpiSsm       *ssm,
                               FpDevice     *dev,
                               GCancellable *cancellable)
{
  goodix_recv_start (ssm, dev, 0, cancellable);
}

/* ========================================================================
 * Command sub-SSM: send → recv ACK → recv data
 * ======================================================================== */

static void
goodix_cmd_ssm_handler (FpiSsm   *ssm,
                        FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixCmd *cmd = self->cmd;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_CMD_SEND:
      goodix_send_message (ssm, dev, cmd->category, cmd->command,
                           cmd->payload, cmd->payload_len, cmd->use_checksum);
      break;

    case GOODIX_CMD_RECV_ACK:
      goodix_recv_start_full (ssm, dev,
                              cmd->ack_optional ? GOODIX_DRAIN_TIMEOUT
                                                : GOODIX_ACK_TIMEOUT,
                              NULL, cmd->ack_optional);
      break;

    case GOODIX_CMD_VALIDATE_ACK:
      {
        g_autoptr(GError) error = NULL;
        guint8 category, command;
        const guint8 *pl;
        gsize pl_len;

        /* Optional ACK (nop) that did not arrive */
        if (cmd->ack_optional && !goodix_proto_rx_complete (&self->rx))
          {
            fpi_ssm_next_state (ssm);
            return;
          }

        /* An FDT event from detection armed earlier (e.g. the idle arm after
         * a scan) can arrive ahead of this command's ACK; drop it and keep
         * waiting for the ACK. */
        if (goodix_proto_rx_parse (&self->rx, &category, &command, &pl, &pl_len) &&
            category == GOODIX_PROTO_CATEGORY_FDT &&
            (command == GOODIX_PROTO_CMD_FDT_DOWN ||
             command == GOODIX_PROTO_CMD_FDT_UP))
          {
            goodix_log_hex ("Dropping stray FDT event while waiting for ACK",
                            pl, pl_len);
            fpi_ssm_jump_to_state (ssm, GOODIX_CMD_RECV_ACK);
            return;
          }

        if (!goodix_validate_ack_for_cmd (dev, cmd, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_CMD_RECV_DATA:
      goodix_recv_start (ssm, dev, GOODIX_DATA_TIMEOUT, NULL);
      break;
    }
}

void
goodix_run_cmd (FpiSsm       *parent_ssm,
                FpDevice     *dev,
                guint8        category,
                guint8        command,
                const guint8 *payload,
                gsize         payload_len,
                gboolean      expect_data)
{
  goodix_run_cmd_full (parent_ssm, dev, category, command, payload,
                       payload_len, TRUE, expect_data, FALSE);
}

void
goodix_run_cmd_full (FpiSsm       *parent_ssm,
                     FpDevice     *dev,
                     guint8        category,
                     guint8        command,
                     const guint8 *payload,
                     gsize         payload_len,
                     gboolean      use_checksum,
                     gboolean      expect_data,
                     gboolean      ack_optional)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  FpiSsm *cmd_ssm;
  GoodixCmd *cmd;

  cmd = g_new0 (GoodixCmd, 1);
  cmd->category = category;
  cmd->command = command;
  cmd->use_checksum = use_checksum;
  cmd->ack_optional = ack_optional;

  if (payload_len > 0 && payload != NULL)
    {
      cmd->payload = g_memdup2 (payload, payload_len);
      cmd->payload_len = payload_len;
    }
  else
    {
      cmd->payload = NULL;
      cmd->payload_len = 0;
    }

  g_free (self->cmd ? self->cmd->payload : NULL);
  g_free (self->cmd);
  self->cmd = cmd;

  cmd_ssm = fpi_ssm_new_full (dev, goodix_cmd_ssm_handler,
                               expect_data ? GOODIX_CMD_NUM_STATES : GOODIX_CMD_RECV_DATA,
                               expect_data ? GOODIX_CMD_NUM_STATES : GOODIX_CMD_RECV_DATA,
                               "goodix-cmd");

  fpi_ssm_start_subsm (parent_ssm, cmd_ssm);
}

gboolean
goodix_parse_reply (FpDevice      *dev,
                    guint8        *out_category,
                    guint8        *out_command,
                    const guint8 **out_payload,
                    gsize         *out_payload_len,
                    GError       **error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  if (goodix_proto_rx_parse (&self->rx, out_category, out_command,
                             out_payload, out_payload_len))
    return TRUE;

  g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Failed to parse device reply");
  return FALSE;
}

gboolean
goodix_parse_reply_exact (FpDevice      *dev,
                          guint8         expected_category,
                          guint8         expected_command,
                          const guint8 **out_payload,
                          gsize         *out_payload_len,
                          GError       **error)
{
  guint8 category, command;

  if (!goodix_parse_reply (dev, &category, &command, out_payload,
                           out_payload_len, error))
    return FALSE;

  if (category != expected_category || command != expected_command)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected reply: cat=0x%02x cmd=0x%02x",
                   category, command);
      return FALSE;
    }

  return TRUE;
}

gboolean
goodix_parse_pack (FpDevice      *dev,
                   guint8         expected_flags,
                   const guint8 **out_data,
                   gsize         *out_len,
                   GError       **error)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  guint8 flags;

  if (!goodix_proto_rx_get_pack (&self->rx, &flags, out_data, out_len))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "Incomplete message pack");
      return FALSE;
    }

  if (flags != expected_flags)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected message pack: expected flags 0x%02x, got 0x%02x",
                   expected_flags, flags);
      return FALSE;
    }

  return TRUE;
}
