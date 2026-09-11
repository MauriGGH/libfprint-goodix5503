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

#pragma once

#include <glib.h>

/* The 5503 wraps every transfer in a message pack (goodix.py):
 *   [flags(1)][length(2 LE)][header_checksum(1)][data(length)]
 *   header_checksum = (flags + length_lo + length_hi) & 0xFF
 * flags 0xA0 carries a protocol message, 0xB0/0xB2 carry TLS records.
 *
 * Protocol message: [cmd_byte(1)][size(2 LE)][payload(N)][checksum(1)]
 * cmd_byte = category<<4 | command<<1
 * size = N + 1
 * checksum = (0xAA - sum(all_bytes)) & 0xFF, or 0x88 when unchecked */

#define GOODIX_PACK_FLAGS_PROTOCOL 0xA0
#define GOODIX_PACK_FLAGS_TLS      0xB0
#define GOODIX_PACK_FLAGS_TLS_DATA 0xB2
#define GOODIX_PACK_HEADER_LEN     4

/* Max reassembly buffer; goodix.py reads up to 0x10000 bytes per message */
#define GOODIX_RX_BUF_SIZE (64 * 1024)

/* --- Reassembly buffer (one message pack) --- */
typedef struct
{
  guint8 *buf;      /* heap-allocated, GOODIX_RX_BUF_SIZE bytes */
  gsize   len;      /* bytes accumulated */
  gsize   expected; /* total pack size from header (including pack header) */
  guint8  flags;    /* pack flags from the first transfer */
} GoodixReassembly;

guint8  *goodix_proto_build_message (guint8   category,
                                     guint8   command,
                                     const guint8 *payload,
                                     gsize    payload_len,
                                     gboolean use_checksum,
                                     gsize   *out_len);

guint8  *goodix_proto_build_pack (guint8        flags,
                                  const guint8 *data,
                                  gsize         data_len,
                                  gsize        *out_len);

gboolean goodix_proto_validate_checksum (const guint8 *data,
                                         gsize         len);

void     goodix_proto_rx_reset (GoodixReassembly *rx);
gboolean goodix_proto_rx_feed_chunk (GoodixReassembly *rx,
                                     const guint8     *chunk,
                                     gsize             chunk_len);
gboolean goodix_proto_rx_complete (GoodixReassembly *rx);

/* Flags and data of the complete pack; out_data points into the reassembly
 * buffer and is only valid until the next receive reset. */
gboolean goodix_proto_rx_get_pack (GoodixReassembly *rx,
                                   guint8           *out_flags,
                                   const guint8    **out_data,
                                   gsize            *out_len);

/* out_payload points into the reassembly buffer — it is only valid until the
 * next receive reset. */
gboolean goodix_proto_rx_parse (GoodixReassembly *rx,
                                guint8           *out_category,
                                guint8           *out_command,
                                const guint8    **out_payload,
                                gsize            *out_payload_len);

void goodix_proto_build_mcu_message (guint32       data_type,
                                     const guint8 *data,
                                     gsize         data_len,
                                     guint8      **out_payload,
                                     gsize        *out_payload_len);

gboolean goodix_proto_parse_mcu_message (const guint8 *payload,
                                         gsize         payload_len,
                                         guint32       expected_type,
                                         const guint8 **out_data,
                                         gsize         *out_data_len);

gboolean goodix_proto_parse_production_read (const guint8  *payload,
                                             gsize          payload_len,
                                             guint32        expected_type,
                                             const guint8 **out_data,
                                             gsize         *out_data_len);
