/*
 * Goodix 53x5 driver for libfprint — Named device commands and reply parsers
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

#include "goodix53x5-private.h"

/* ========================================================================
 * Named device commands
 *
 * These wrap goodix_run_cmd() so action modules read as device operations
 * instead of category/command bytes and hand-built payloads. Commands that
 * expect a data reply have a matching named reply parser below; commands
 * documented as "ACK only" advance the parent SSM after ACK validation.
 * ======================================================================== */

/* Send a nop. The ACK is optional; the 5503 usually sends none. */
void goodix_cmd_ping (FpiSsm *ssm, FpDevice *dev);

/* Read the firmware version string. Expects data. */
void goodix_cmd_read_fw_version (FpiSsm *ssm, FpDevice *dev);

/* Reset the sensor (not the MCU). Expects data ([status][number LE16]). */
void goodix_cmd_reset_sensor (FpiSsm *ssm, FpDevice *dev);

/* Read 4 bytes of chip ID from register address 0. Expects data. */
void goodix_cmd_read_chip_id (FpiSsm *ssm, FpDevice *dev);

/* Read the OTP calibration block. Expects data. */
void goodix_cmd_read_otp (FpiSsm *ssm, FpDevice *dev);

/* Production read of @read_type (e.g. GOODIX_PSK_READ_FLAGS = PSK hash).
 * Expects data. */
void goodix_cmd_production_read (FpiSsm *ssm, FpDevice *dev,
                                 guint32 read_type);

/* Production write of @data under @data_type (e.g. GOODIX_PSK_WRITE_FLAGS =
 * PSK white box). Expects data (a one-byte status reply). */
void goodix_cmd_production_write (FpiSsm *ssm, FpDevice *dev,
                                  guint32 data_type,
                                  const guint8 *data, gsize data_len);

/* Send an MCU envelope of @data_type (GTLS handshake traffic). ACK only;
 * the device replies asynchronously via a plain receive. */
void goodix_cmd_mcu_send (FpiSsm *ssm, FpDevice *dev, guint32 data_type,
                          const guint8 *data, gsize data_len);

/* Upload the (patched) sensor config blob. Expects data (success flag). */
void goodix_cmd_upload_config (FpiSsm *ssm, FpDevice *dev,
                               const guint8 *config, gsize config_len);

/* Arm finger-down detection with @fdt_base. ACK only; the FDT event arrives
 * later via a cancellable receive. */
void goodix_cmd_fdt_down_setup (FpiSsm *ssm, FpDevice *dev,
                                const guint8 *fdt_base);

/* Arm finger-up detection with @fdt_base. ACK only; the FDT event arrives
 * later via a cancellable receive. */
void goodix_cmd_fdt_up_setup (FpiSsm *ssm, FpDevice *dev,
                              const guint8 *fdt_base);

/* Run a manual FDT check against @fdt_base, with sensor TX on or off.
 * Expects data (irq status, touch flag and live FDT data). */
void goodix_cmd_fdt_manual (FpiSsm *ssm, FpDevice *dev,
                            gboolean tx_enable, const guint8 *fdt_base);

/* Request an image frame. Expects data (the encrypted frame). */
void goodix_cmd_request_image (FpiSsm *ssm, FpDevice *dev,
                               gboolean tx_enable, gboolean hv_enable,
                               gboolean is_finger, guint16 dac);

/* Put the MCU into sleep mode. ACK only. */
void goodix_cmd_set_sleep_mode (FpiSsm *ssm, FpDevice *dev);

/* Switch sensor EC power on or off. Expects data (success flag). */
void goodix_cmd_ec_control (FpiSsm *ssm, FpDevice *dev, gboolean on);

/* Ask the sensor to start TLS. ACK only; the sensor then sends its
 * ClientHello in a 0xB0 pack, fetched with a plain receive. */
void goodix_cmd_request_tls_connection (FpiSsm *ssm, FpDevice *dev);

/* Read the POV image state. Expects data ([state]). */
void goodix_cmd_mcu_get_pov_image (FpiSsm *ssm, FpDevice *dev);

/* Switch the MCU to FDT mode with the raw @mode payload from driver_5503.py.
 * Expects data. */
void goodix_cmd_mcu_switch_to_fdt_mode (FpiSsm *ssm, FpDevice *dev,
                                        const guint8 *mode, gsize mode_len);

/* Request an image frame. Expects data: a 0xB2 pack whose data carries the
 * TLS-encrypted frame after a 9-byte prefix. */
void goodix_cmd_mcu_get_image (FpiSsm *ssm, FpDevice *dev,
                               const guint8 *payload, gsize payload_len);

/* Query the MCU state with the raw @payload from driver_5503.py. Expects
 * data. */
void goodix_cmd_query_mcu_state (FpiSsm *ssm, FpDevice *dev,
                                 const guint8 *payload, gsize payload_len);

/* Run the POV image check. Expects data ([state]). */
void goodix_cmd_pov_image_check (FpiSsm *ssm, FpDevice *dev);

/* Arm finger-down / finger-up detection with the raw @mode payload from
 * driver_5503.py. ACK only; the FDT event arrives later via a plain
 * receive. */
void goodix_cmd_mcu_switch_to_fdt_down (FpiSsm *ssm, FpDevice *dev,
                                        const guint8 *mode, gsize mode_len);
void goodix_cmd_mcu_switch_to_fdt_up (FpiSsm *ssm, FpDevice *dev,
                                      const guint8 *mode, gsize mode_len);

/* Set driver state (command 0xC4, category 0xC, cmd 0x2, payload \x01\x00). ACK only. */
void goodix_cmd_set_drv_state (FpiSsm *ssm, FpDevice *dev);

/* ========================================================================
 * Named reply parsers
 *
 * All returned payload pointers point into the current RX buffer and are
 * valid only until the next receive reset.
 * ======================================================================== */

gboolean goodix_cmd_parse_fw_version_reply (FpDevice      *dev,
                                            const guint8 **out_payload,
                                            gsize         *out_payload_len,
                                            GError       **error);

gboolean goodix_cmd_parse_chip_id_reply (FpDevice      *dev,
                                         const guint8 **out_payload,
                                         gsize         *out_payload_len,
                                         GError       **error);

gboolean goodix_cmd_parse_otp_reply (FpDevice      *dev,
                                     const guint8 **out_payload,
                                     gsize         *out_payload_len,
                                     GError       **error);

gboolean goodix_cmd_parse_production_read_reply (FpDevice      *dev,
                                                 guint32        read_type,
                                                 const guint8 **out_data,
                                                 gsize         *out_data_len);

gboolean goodix_cmd_parse_production_write_reply (FpDevice      *dev,
                                                  guint32        data_type,
                                                  const guint8 **out_payload,
                                                  gsize         *out_payload_len);

gboolean goodix_cmd_parse_mcu_reply (FpDevice      *dev,
                                     guint32        expected_type,
                                     const guint8 **out_data,
                                     gsize         *out_data_len);

/* TRUE if the config upload reply reports success. */
gboolean goodix_cmd_parse_config_reply (FpDevice *dev);

/* TRUE if the EC power control reply reports success. */
gboolean goodix_cmd_parse_ec_control_reply (FpDevice *dev);

/* Parse a manual FDT reading returned by goodix_cmd_fdt_manual(). */
gboolean goodix_cmd_parse_fdt_manual_reply (FpDevice      *dev,
                                             const guint8 **out_payload,
                                             gsize         *out_payload_len,
                                             GError       **error);

/* Parse an FDT down/up event delivered after goodix_cmd_fdt_down_setup() /
 * goodix_cmd_fdt_up_setup(). The payload layout is
 * [irq_status(2)][touch_flag(2)][fdt_data(GOODIX_FDT_BASE_LEN)]. */
gboolean goodix_cmd_parse_fdt_event (FpDevice      *dev,
                                     gboolean       up,
                                     const guint8 **out_payload,
                                     gsize         *out_payload_len,
                                     GError       **error);
