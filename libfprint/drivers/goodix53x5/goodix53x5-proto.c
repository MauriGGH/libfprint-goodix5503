/*
 * Goodix 53x5 driver for libfprint — Protocol layer
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
#include "goodix53x5-proto.h"

/*
 * Message format: [cmd_byte(1)][size(2 LE)][payload(N)][checksum(1)]
 *   cmd_byte = category<<4 | command<<1
 *   size = len(payload) + 1 (for the checksum byte)
 *   checksum = (0xAA - sum(cmd_byte, size_lo, size_hi, payload...)) & 0xFF
 *              or 0x88 for handshake messages
 */

/**
 * goodix_proto_build_message:
 *
 * Build a complete protocol message ready for chunked USB transmission.
 * Returns a newly allocated buffer. The caller must free it with g_free().
 */
guint8 *
goodix_proto_build_message (guint8        category,
                            guint8        command,
                            const guint8 *payload,
                            gsize         payload_len,
                            gboolean      use_checksum,
                            gsize        *out_len)
{
  guint8 cmd_byte = (category << 4) | (command << 1);
  guint16 size_field = (guint16) (payload_len + 1); /* +1 for checksum */
  gsize total = 1 + 2 + payload_len + 1;            /* cmd + size(2) + payload + checksum */
  guint8 *msg = g_malloc (total);
  guint8 checksum;
  guint sum;

  msg[0] = cmd_byte;
  msg[1] = size_field & 0xFF;
  msg[2] = (size_field >> 8) & 0xFF;

  if (payload_len > 0)
    memcpy (msg + 3, payload, payload_len);

  if (use_checksum)
    {
      sum = 0;
      for (gsize i = 0; i < total - 1; i++)
        sum += msg[i];
      checksum = (0xAA - sum) & 0xFF;
    }
  else
    {
      checksum = 0x88;
    }

  msg[total - 1] = checksum;

  *out_len = total;
  return msg;
}

/**
 * goodix_proto_build_pack:
 *
 * Wrap data in a message pack: [flags][length(2 LE)][header checksum][data].
 * Returns a newly allocated buffer. The caller must free it with g_free().
 */
guint8 *
goodix_proto_build_pack (guint8        flags,
                         const guint8 *data,
                         gsize         data_len,
                         gsize        *out_len)
{
  gsize total = GOODIX_PACK_HEADER_LEN + data_len;
  guint8 *pack = g_malloc (total);

  g_assert (data_len <= G_MAXUINT16);

  pack[0] = flags;
  pack[1] = data_len & 0xFF;
  pack[2] = (data_len >> 8) & 0xFF;
  pack[3] = (pack[0] + pack[1] + pack[2]) & 0xFF;

  if (data_len > 0)
    memcpy (pack + GOODIX_PACK_HEADER_LEN, data, data_len);

  *out_len = total;
  return pack;
}

/**
 * goodix_proto_validate_checksum:
 *
 * Validate checksum of a complete received message.
 * data must include the full message including the checksum byte.
 */
gboolean
goodix_proto_validate_checksum (const guint8 *data,
                                gsize         len)
{
  guint8 msg_checksum;
  guint sum;
  guint8 computed;

  if (len < 4)
    return FALSE;

  msg_checksum = data[len - 1];

  /* 0x88 = no-checksum marker (handshake) */
  if (msg_checksum == 0x88)
    return TRUE;

  sum = 0;
  for (gsize i = 0; i < len - 1; i++)
    sum += data[i];

  computed = (0xAA - sum) & 0xFF;
  return computed == msg_checksum;
}

/**
 * goodix_proto_rx_reset:
 *
 * Reset the reassembly buffer for a new message.
 */
void
goodix_proto_rx_reset (GoodixReassembly *rx)
{
  if (rx->buf == NULL)
    rx->buf = g_malloc (GOODIX_RX_BUF_SIZE);
  rx->len = 0;
  rx->expected = 0;
  rx->flags = 0;
}

/**
 * goodix_proto_rx_feed_chunk:
 *
 * Feed a USB IN transfer into the reassembly buffer. The first transfer
 * starts with the message pack header; later transfers are raw continuation
 * bytes of the same pack.
 * Returns TRUE if the chunk was accepted, FALSE on protocol error.
 */
gboolean
goodix_proto_rx_feed_chunk (GoodixReassembly *rx,
                            const guint8     *chunk,
                            gsize             chunk_len)
{
  if (chunk_len == 0)
    return TRUE;

  if (rx->len == 0)
    {
      guint16 pack_len;

      if (chunk_len < GOODIX_PACK_HEADER_LEN)
        return FALSE;

      if (((chunk[0] + chunk[1] + chunk[2]) & 0xFF) != chunk[3])
        {
          fp_warn ("Message pack header checksum mismatch: %02x %02x %02x %02x",
                   chunk[0], chunk[1], chunk[2], chunk[3]);
          return FALSE;
        }

      rx->flags = chunk[0];
      pack_len = chunk[1] | ((guint16) chunk[2] << 8);
      rx->expected = GOODIX_PACK_HEADER_LEN + (gsize) pack_len;
    }

  if (rx->len + chunk_len > GOODIX_RX_BUF_SIZE)
    return FALSE;

  memcpy (rx->buf + rx->len, chunk, chunk_len);
  rx->len += chunk_len;

  return TRUE;
}

/**
 * goodix_proto_rx_complete:
 *
 * Check if the reassembly buffer has a complete message.
 */
gboolean
goodix_proto_rx_complete (GoodixReassembly *rx)
{
  if (rx->expected == 0)
    return FALSE;

  /* We need at least 'expected' bytes. We may have more due to
   * USB padding in the last chunk. */
  return rx->len >= rx->expected;
}

/**
 * goodix_proto_rx_get_pack:
 *
 * Get the flags and data of the complete message pack.
 */
gboolean
goodix_proto_rx_get_pack (GoodixReassembly *rx,
                          guint8           *out_flags,
                          const guint8    **out_data,
                          gsize            *out_len)
{
  if (!goodix_proto_rx_complete (rx))
    return FALSE;

  *out_flags = rx->flags;
  *out_data = rx->buf + GOODIX_PACK_HEADER_LEN;
  *out_len = rx->expected - GOODIX_PACK_HEADER_LEN;

  return TRUE;
}

/**
 * goodix_proto_rx_parse:
 *
 * Parse the complete reassembled message.
 * out_payload points into the rx buffer — valid until rx is reset.
 */
gboolean
goodix_proto_rx_parse (GoodixReassembly *rx,
                       guint8           *out_category,
                       guint8           *out_command,
                       const guint8    **out_payload,
                       gsize            *out_payload_len)
{
  const guint8 *msg;
  gsize pack_len, msg_len;

  if (!goodix_proto_rx_complete (rx))
    return FALSE;

  if (rx->flags != GOODIX_PACK_FLAGS_PROTOCOL)
    {
      fp_warn ("Expected a protocol message pack, got flags 0x%02x", rx->flags);
      return FALSE;
    }

  msg = rx->buf + GOODIX_PACK_HEADER_LEN;
  pack_len = rx->expected - GOODIX_PACK_HEADER_LEN;

  if (pack_len < 4)
    return FALSE;

  /* size field stores payload + checksum */
  msg_len = 3 + (gsize) (msg[1] | ((guint16) msg[2] << 8));

  if (msg_len < 4 || msg_len > pack_len)
    {
      fp_warn ("Protocol message length %zu does not fit pack length %zu",
               msg_len, pack_len);
      return FALSE;
    }

  if (!goodix_proto_validate_checksum (msg, msg_len))
    {
      fp_warn ("Message checksum validation failed");
      return FALSE;
    }

  *out_category = msg[0] >> 4;
  *out_command = (msg[0] & 0x0F) >> 1;

  /* Payload starts at offset 3, ends before checksum */
  *out_payload = msg + 3;
  *out_payload_len = msg_len - 4; /* minus cmd(1) + size(2) + checksum(1) */

  return TRUE;
}

/**
 * goodix_proto_build_mcu_message:
 *
 * Build an MCU envelope payload.
 * Format: [data_type(4 LE)][total_size(4 LE)][data]
 * where total_size = len(data) + 8 (includes the header).
 */
void
goodix_proto_build_mcu_message (guint32       data_type,
                                const guint8 *data,
                                gsize         data_len,
                                guint8      **out_payload,
                                gsize        *out_payload_len)
{
  gsize total = 4 + 4 + data_len;
  guint8 *buf = g_malloc (total);
  guint32 size_val = (guint32) (data_len + 8);

  buf[0] = data_type & 0xFF;
  buf[1] = (data_type >> 8) & 0xFF;
  buf[2] = (data_type >> 16) & 0xFF;
  buf[3] = (data_type >> 24) & 0xFF;

  buf[4] = size_val & 0xFF;
  buf[5] = (size_val >> 8) & 0xFF;
  buf[6] = (size_val >> 16) & 0xFF;
  buf[7] = (size_val >> 24) & 0xFF;

  if (data_len > 0)
    memcpy (buf + 8, data, data_len);

  *out_payload = buf;
  *out_payload_len = total;
}

/**
 * goodix_proto_parse_mcu_message:
 *
 * Parse an MCU envelope from a received message payload.
 * The received payload (from category=0xD, command=1) has format:
 * [data_type(4 LE)][payload_size(4 LE)][data]
 * where payload_size = total including the 8-byte header.
 */
gboolean
goodix_proto_parse_mcu_message (const guint8  *payload,
                                gsize          payload_len,
                                guint32        expected_type,
                                const guint8 **out_data,
                                gsize         *out_data_len)
{
  guint32 msg_type, msg_size;

  if (payload_len < 8)
    return FALSE;

  msg_type = payload[0] | ((guint32) payload[1] << 8) |
             ((guint32) payload[2] << 16) | ((guint32) payload[3] << 24);

  if (msg_type != expected_type)
    {
      fp_warn ("MCU message type mismatch: expected 0x%x, got 0x%x",
               expected_type, msg_type);
      return FALSE;
    }

  msg_size = payload[4] | ((guint32) payload[5] << 8) |
             ((guint32) payload[6] << 16) | ((guint32) payload[7] << 24);

  if (msg_size != (guint32) payload_len)
    {
      fp_warn ("MCU message size mismatch: header says %u, got %zu",
               msg_size, payload_len);
      return FALSE;
    }

  *out_data = payload + 8;
  *out_data_len = payload_len - 8;
  return TRUE;
}

/**
 * goodix_proto_parse_production_read:
 *
 * Parse a production_read reply payload.
 * Format: [status(1)][read_type(4 LE)][data_size(4 LE)][data]
 */
gboolean
goodix_proto_parse_production_read (const guint8  *payload,
                                    gsize          payload_len,
                                    guint32        expected_type,
                                    const guint8 **out_data,
                                    gsize         *out_data_len)
{
  guint32 msg_type, data_size;

  if (payload_len < 9)
    return FALSE;

  if (payload[0] != 0)
    {
      fp_warn ("Production read MCU failed, status: %d", payload[0]);
      return FALSE;
    }

  msg_type = payload[1] | ((guint32) payload[2] << 8) |
             ((guint32) payload[3] << 16) | ((guint32) payload[4] << 24);

  if (msg_type != expected_type)
    {
      fp_warn ("Production read type mismatch: expected 0x%x, got 0x%x",
               expected_type, msg_type);
      return FALSE;
    }

  data_size = payload[5] | ((guint32) payload[6] << 8) |
              ((guint32) payload[7] << 16) | ((guint32) payload[8] << 24);

  if (data_size != payload_len - 9)
    {
      fp_warn ("Production read size mismatch: %u != %zu",
               data_size, payload_len - 9);
      return FALSE;
    }

  *out_data = payload + 9;
  *out_data_len = data_size;
  return TRUE;
}
