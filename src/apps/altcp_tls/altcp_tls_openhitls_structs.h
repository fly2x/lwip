/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains structure definitions for a TLS layer using openHiTLS.
 */

/*
 * Copyright (c) 2024 lwIP contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 */
#ifndef LWIP_HDR_ALTCP_OPENHITLS_STRUCTS_H
#define LWIP_HDR_ALTCP_OPENHITLS_STRUCTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_openhitls_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_OPENHITLS

#include "lwip/altcp.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Include openHiTLS headers */
#include "hitls/tls/hitls.h"
#include "hitls/tls/hitls_config.h"
#include "hitls/tls/hitls_cert.h"
#include "hitls/tls/hitls_crypt_type.h"
#include "hitls/tls/hitls_session.h"
#include "hitls/tls/hitls_error.h"
#include "hitls/pki/hitls_pki_cert.h"
#include "hitls/pki/hitls_pki_types.h"
#include "hitls/crypto/crypt_eal_pkey.h"
#include "bsl_uio.h"
#include "bsl_types.h"

/** TLS configuration structure for openHiTLS */
struct altcp_tls_config {
  /** openHiTLS configuration object */
  HITLS_Config *hitls_config;
  
  /** Certificate chain */
  HITLS_X509_Cert *cert_chain;
  
  /** Private key */
  HITLS_CRYPT_Key *private_key;
  
  /** CA certificate for client verification */
  HITLS_X509_Cert *ca_cert;
  
  /** Certificate count */
  u8_t cert_count;
  
  /** Maximum certificates allowed */
  u8_t cert_max;
  
  /** Private key count */
  u8_t pkey_count;
  
  /** Maximum private keys allowed */
  u8_t pkey_max;
  
#if ALTCP_OPENHITLS_USE_SESSION_CACHE
  /** Session cache if enabled */
  void *session_cache;
#endif
};

/** TLS connection state for openHiTLS */
typedef struct altcp_openhitls_state_s {
  /** Configuration reference */
  void *conf;
  
  /** openHiTLS context */
  HITLS_Ctx *hitls_ctx;
  
  /** UIO object for I/O operations */
  BSL_UIO *uio;
  
  /** Receive buffer chain (encrypted data from network) */
  struct pbuf *rx;
  
  /** Application data buffer (decrypted data for application) */
  struct pbuf *rx_app;
  
  /** Connection state flags */
  u8_t flags;
  
  /** Flow control and accounting */
  int rx_passed_unrecved;
  int bio_bytes_read;
  int bio_bytes_appl;
  int overhead_bytes_adjust;
} altcp_openhitls_state_t;

/** Connection state flags */
#define ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE    0x01
#define ALTCP_OPENHITLS_FLAGS_UPPER_CALLED      0x02
#define ALTCP_OPENHITLS_FLAGS_RX_CLOSE_QUEUED   0x04
#define ALTCP_OPENHITLS_FLAGS_RX_CLOSED         0x08

/** Session structure for compatibility */
struct altcp_tls_session {
  HITLS_Session *hitls_session;
};

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_OPENHITLS */
#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_OPENHITLS_STRUCTS_H */