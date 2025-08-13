/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains memory management functions for openHiTLS integration.
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

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "altcp_tls_openhitls_mem.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_OPENHITLS

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/debug.h"

#include <string.h>

/**
 * Initialize memory management for openHiTLS
 */
void
altcp_openhitls_mem_init(void)
{
  /* Nothing to do for now - lwIP memory management is already initialized */
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_mem_init: initialized\n"));
}

/**
 * Custom malloc function for openHiTLS
 */
void*
altcp_openhitls_malloc(size_t size)
{
  void *ptr;
  
  /* Use lwIP's memory allocator */
  ptr = mem_malloc((mem_size_t)size);
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_malloc: allocated %"SZT_F" bytes at %p\n", size, ptr));
  
  return ptr;
}

/**
 * Custom free function for openHiTLS
 */
void
altcp_openhitls_free(void* ptr)
{
  if (ptr != NULL) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_free: freeing %p\n", ptr));
    mem_free(ptr);
  }
}

/**
 * Custom realloc function for openHiTLS
 */
void*
altcp_openhitls_realloc(void* ptr, size_t size)
{
  void *new_ptr;
  
  if (ptr == NULL) {
    /* realloc(NULL, size) is equivalent to malloc(size) */
    return altcp_openhitls_malloc(size);
  }
  
  if (size == 0) {
    /* realloc(ptr, 0) is equivalent to free(ptr) */
    altcp_openhitls_free(ptr);
    return NULL;
  }
  
  /* lwIP doesn't have realloc, so we need to allocate new memory and copy */
  new_ptr = altcp_openhitls_malloc(size);
  if (new_ptr != NULL) {
    /* Copy the old data - we don't know the original size, so we assume
     * the new size is smaller or equal to the old size. This is a limitation
     * of lwIP's memory management. */
    memcpy(new_ptr, ptr, size);
    altcp_openhitls_free(ptr);
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_realloc: reallocated %p to %"SZT_F" bytes at %p\n", ptr, size, new_ptr));
  
  return new_ptr;
}

/**
 * Custom calloc function for openHiTLS
 */
void*
altcp_openhitls_calloc(size_t num, size_t size)
{
  void *ptr;
  size_t total_size;
  
  /* Check for overflow */
  if (num != 0 && size > SIZE_MAX / num) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_calloc: overflow detected\n"));
    return NULL;
  }
  
  total_size = num * size;
  ptr = altcp_openhitls_malloc(total_size);
  
  if (ptr != NULL) {
    /* Zero the allocated memory */
    memset(ptr, 0, total_size);
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_calloc: allocated %"SZT_F" * %"SZT_F" bytes at %p\n", num, size, ptr));
  
  return ptr;
}

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_OPENHITLS */
#endif /* LWIP_ALTCP */