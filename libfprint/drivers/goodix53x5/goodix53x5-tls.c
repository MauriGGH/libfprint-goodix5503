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

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "goodix53x5-tls.h"

#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define GOODIX_TLS_PSK_MAX_LEN 64

struct _GoodixTls
{
  SSL_CTX *ctx;
  SSL     *ssl;
  BIO     *rbio; /* records from the sensor, owned by ssl */
  BIO     *wbio; /* records for the sensor, owned by ssl */
  guint8   psk[GOODIX_TLS_PSK_MAX_LEN];
  gsize    psk_len;
};

static void
goodix_tls_set_error (GError     **error,
                      const gchar *what)
{
  g_autoptr(GString) msg = g_string_new (what);
  unsigned long err;

  while ((err = ERR_get_error ()) != 0)
    {
      char buf[256];

      ERR_error_string_n (err, buf, sizeof (buf));
      g_string_append_printf (msg, ": %s", buf);
    }

  g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, msg->str);
}

static const gchar *
goodix_tls_handshake_name (guint8 type)
{
  switch (type)
    {
    case SSL3_MT_CLIENT_HELLO:
      return "ClientHello";

    case SSL3_MT_SERVER_HELLO:
      return "ServerHello";

    case SSL3_MT_NEWSESSION_TICKET:
      return "NewSessionTicket";

    case SSL3_MT_ENCRYPTED_EXTENSIONS:
      return "EncryptedExtensions";

    case SSL3_MT_CERTIFICATE:
      return "Certificate";

    case SSL3_MT_SERVER_KEY_EXCHANGE:
      return "ServerKeyExchange";

    case SSL3_MT_CERTIFICATE_REQUEST:
      return "CertificateRequest";

    case SSL3_MT_SERVER_DONE:
      return "ServerHelloDone";

    case SSL3_MT_CLIENT_KEY_EXCHANGE:
      return "ClientKeyExchange";

    case SSL3_MT_FINISHED:
      return "Finished";

    default:
      return "unknown handshake message";
    }
}

/* Logs each handshake message, ChangeCipherSpec and alert as OpenSSL reads
 * it from the sensor's records or writes it into records for the sensor. */
static void
goodix_tls_msg_cb (int         write_p,
                   int         version,
                   int         content_type,
                   const void *buf,
                   size_t      len,
                   SSL        *ssl,
                   void       *arg)
{
  const guint8 *msg = buf;
  const gchar *dir = write_p ? "-> sensor" : "<- sensor";

  switch (content_type)
    {
    case SSL3_RT_HANDSHAKE:
      if (len > 0)
        fp_dbg ("TLS %s: %s (%zu bytes)", dir,
                goodix_tls_handshake_name (msg[0]), len);
      break;

    case SSL3_RT_CHANGE_CIPHER_SPEC:
      fp_dbg ("TLS %s: ChangeCipherSpec", dir);
      break;

    case SSL3_RT_ALERT:
      if (len >= 2)
        fp_warn ("TLS %s: %s alert: %s", dir,
                 SSL_alert_type_string_long (msg[0] << 8),
                 SSL_alert_desc_string_long (msg[1]));
      break;

    default:
      /* Record headers and TLS 1.3 inner content types */
      break;
    }
}

static unsigned int
goodix_tls_psk_server_cb (SSL           *ssl,
                          const char    *identity,
                          unsigned char *psk,
                          unsigned int   max_psk_len)
{
  GoodixTls *tls = SSL_get_app_data (ssl);

  /* Like openssl s_server, accept whatever identity the sensor sends */
  fp_dbg ("TLS PSK identity from sensor: \"%s\"",
          identity ? identity : "(none)");

  if (tls->psk_len > max_psk_len)
    return 0;

  memcpy (psk, tls->psk, tls->psk_len);
  return tls->psk_len;
}

GoodixTls *
goodix_tls_new (const guint8 *psk,
                gsize         psk_len,
                GError      **error)
{
  GoodixTls *tls;
  BIO *rbio, *wbio;

  g_return_val_if_fail (psk_len <= GOODIX_TLS_PSK_MAX_LEN, NULL);

  ERR_clear_error ();

  tls = g_new0 (GoodixTls, 1);
  memcpy (tls->psk, psk, psk_len);
  tls->psk_len = psk_len;

  /* Mirror `openssl s_server -nocert -psk <psk>` from driver_5503.py:
   * default protocol versions and ciphers, no certificate, PSK only. */
  tls->ctx = SSL_CTX_new (TLS_server_method ());
  if (tls->ctx)
    {
      SSL_CTX_set_psk_server_callback (tls->ctx, goodix_tls_psk_server_cb);
      tls->ssl = SSL_new (tls->ctx);
    }

  if (!tls->ssl)
    {
      goodix_tls_set_error (error, "Failed to create TLS server");
      goodix_tls_free (tls);
      return NULL;
    }

  rbio = BIO_new (BIO_s_mem ());
  wbio = BIO_new (BIO_s_mem ());
  if (!rbio || !wbio)
    {
      BIO_free (rbio);
      BIO_free (wbio);
      goodix_tls_set_error (error, "Failed to create TLS memory BIOs");
      goodix_tls_free (tls);
      return NULL;
    }

  /* An empty read BIO means "wait for the next USB pack", not EOF */
  BIO_set_mem_eof_return (rbio, -1);
  BIO_set_mem_eof_return (wbio, -1);

  SSL_set_bio (tls->ssl, rbio, wbio);
  tls->rbio = rbio;
  tls->wbio = wbio;

  SSL_set_app_data (tls->ssl, tls);
  SSL_set_msg_callback (tls->ssl, goodix_tls_msg_cb);
  SSL_set_accept_state (tls->ssl);

  return tls;
}

void
goodix_tls_free (GoodixTls *tls)
{
  if (!tls)
    return;

  SSL_free (tls->ssl); /* also frees both BIOs */
  SSL_CTX_free (tls->ctx);
  OPENSSL_cleanse (tls->psk, sizeof (tls->psk));
  g_free (tls);
}

gboolean
goodix_tls_handshake_step (GoodixTls    *tls,
                           const guint8 *in,
                           gsize         in_len,
                           guint8      **out,
                           gsize        *out_len,
                           GError      **error)
{
  size_t pending;
  int ret;

  *out = NULL;
  *out_len = 0;

  ERR_clear_error ();

  if (in_len > 0 && BIO_write (tls->rbio, in, in_len) != (int) in_len)
    {
      goodix_tls_set_error (error, "Failed to buffer TLS records from sensor");
      return FALSE;
    }

  ret = SSL_do_handshake (tls->ssl);
  if (ret != 1)
    {
      int ssl_err = SSL_get_error (tls->ssl, ret);

      if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE)
        {
          g_autofree gchar *what =
            g_strdup_printf ("TLS handshake failed (SSL error %d)", ssl_err);

          goodix_tls_set_error (error, what);
          return FALSE;
        }
    }

  pending = BIO_ctrl_pending (tls->wbio);
  if (pending > 0)
    {
      g_autofree guint8 *buf = g_malloc (pending);
      int n = BIO_read (tls->wbio, buf, (int) pending);

      if (n <= 0)
        {
          goodix_tls_set_error (error, "Failed to collect TLS records for sensor");
          return FALSE;
        }

      *out = g_steal_pointer (&buf);
      *out_len = n;
    }

  return TRUE;
}

gboolean
goodix_tls_handshake_done (GoodixTls *tls)
{
  return SSL_is_init_finished (tls->ssl);
}

gboolean
goodix_tls_decrypt (GoodixTls    *tls,
                    const guint8 *in,
                    gsize         in_len,
                    guint8      **out,
                    gsize        *out_len,
                    GError      **error)
{
  g_autoptr(GByteArray) plain = g_byte_array_new ();
  guint8 buf[4096];
  int n, ssl_err;

  *out = NULL;
  *out_len = 0;

  ERR_clear_error ();

  if (BIO_write (tls->rbio, in, in_len) != (int) in_len)
    {
      goodix_tls_set_error (error, "Failed to buffer TLS records from sensor");
      return FALSE;
    }

  while ((n = SSL_read (tls->ssl, buf, sizeof (buf))) > 0)
    g_byte_array_append (plain, buf, n);

  /* WANT_READ: all buffered records consumed */
  ssl_err = SSL_get_error (tls->ssl, n);
  if (ssl_err != SSL_ERROR_WANT_READ)
    {
      g_autofree gchar *what =
        g_strdup_printf ("TLS decrypt failed (SSL error %d)", ssl_err);

      goodix_tls_set_error (error, what);
      return FALSE;
    }

  *out_len = plain->len;
  *out = g_byte_array_free (g_steal_pointer (&plain), FALSE);
  return TRUE;
}

const gchar *
goodix_tls_get_version (GoodixTls *tls)
{
  return SSL_get_version (tls->ssl);
}

const gchar *
goodix_tls_get_cipher (GoodixTls *tls)
{
  return SSL_get_cipher_name (tls->ssl);
}
