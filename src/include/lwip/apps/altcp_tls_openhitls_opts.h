/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains options for an openHiTLS port of the TLS layer.
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
#ifndef LWIP_HDR_ALTCP_TLS_OPENHITLS_OPTS_H
#define LWIP_HDR_ALTCP_TLS_OPENHITLS_OPTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

/** LWIP_ALTCP_TLS_OPENHITLS==1: use openHiTLS for TLS support for altcp API
 * openHiTLS include directory must be reachable via include search path
 */
#ifndef LWIP_ALTCP_TLS_OPENHITLS
#define LWIP_ALTCP_TLS_OPENHITLS                        0
#endif

/** Configure debug level for this file */
#ifndef ALTCP_OPENHITLS_DEBUG
#define ALTCP_OPENHITLS_DEBUG                   LWIP_DBG_OFF
#endif

/** Set a session timeout in seconds for openHiTLS */
#ifndef ALTCP_OPENHITLS_SESSION_TIMEOUT_SECONDS
#define ALTCP_OPENHITLS_SESSION_TIMEOUT_SECONDS (60 * 60)
#endif

/** Use session cache for openHiTLS */
#ifndef ALTCP_OPENHITLS_USE_SESSION_CACHE
#define ALTCP_OPENHITLS_USE_SESSION_CACHE       0
#endif

/** Session cache size for openHiTLS */
#ifndef ALTCP_OPENHITLS_SESSION_CACHE_SIZE
#define ALTCP_OPENHITLS_SESSION_CACHE_SIZE      30
#endif

/** Maximum number of certificates per configuration */
#ifndef ALTCP_OPENHITLS_MAX_CERTS
#define ALTCP_OPENHITLS_MAX_CERTS               10
#endif

/** Maximum number of private keys per configuration */
#ifndef ALTCP_OPENHITLS_MAX_PRIVKEYS
#define ALTCP_OPENHITLS_MAX_PRIVKEYS            10
#endif

/** Enable/disable certificate verification */
#ifndef ALTCP_OPENHITLS_VERIFY_CERTS
#define ALTCP_OPENHITLS_VERIFY_CERTS            1
#endif

/** Enable hostname verification for client connections */
#ifndef ALTCP_OPENHITLS_VERIFY_HOSTNAME
#define ALTCP_OPENHITLS_VERIFY_HOSTNAME         1
#endif

/** Default read buffer size */
#ifndef ALTCP_OPENHITLS_READ_BUFFER_SIZE
#define ALTCP_OPENHITLS_READ_BUFFER_SIZE        4096
#endif

/** Default write buffer size */
#ifndef ALTCP_OPENHITLS_WRITE_BUFFER_SIZE
#define ALTCP_OPENHITLS_WRITE_BUFFER_SIZE       4096
#endif

#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_TLS_OPENHITLS_OPTS_H */