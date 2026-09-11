/*
 * Goodix 53x5 driver for libfprint — TLS-PSK session (5503)
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

/*
 * Server side of the TLS-PSK session the 5503 opens after
 * request_tls_connection. The sensor is the TLS client. Its records arrive
 * in 0xB0 message packs and are fed to OpenSSL through a memory BIO; the
 * records OpenSSL writes are collected from another memory BIO and sent back
 * in 0xB0 packs. This replaces the `openssl s_server -nocert -psk` process
 * and TCP bridge used by driver_5503.py.
 */
typedef struct _GoodixTls GoodixTls;

GoodixTls *goodix_tls_new (const guint8 *psk,
                           gsize         psk_len,
                           GError      **error);

void       goodix_tls_free (GoodixTls *tls);

/* Feed TLS records received from the sensor (@in_len may be 0) and advance
 * the handshake. On success *out holds the records to send to the sensor,
 * or NULL if there are none; free it with g_free(). */
gboolean   goodix_tls_handshake_step (GoodixTls    *tls,
                                      const guint8 *in,
                                      gsize         in_len,
                                      guint8      **out,
                                      gsize        *out_len,
                                      GError      **error);

gboolean   goodix_tls_handshake_done (GoodixTls *tls);

/* Feed application-data records from the sensor and decrypt them. On
 * success *out holds all plaintext available so far; free it with g_free(). */
gboolean   goodix_tls_decrypt (GoodixTls    *tls,
                               const guint8 *in,
                               gsize         in_len,
                               guint8      **out,
                               gsize        *out_len,
                               GError      **error);

/* Negotiated protocol version and cipher suite names, for logging */
const gchar *goodix_tls_get_version (GoodixTls *tls);
const gchar *goodix_tls_get_cipher (GoodixTls *tls);
