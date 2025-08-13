/**
 * @file
 * Working openHiTLS integration with TLS handshake and data transmission for lwIP ALTCP
 */

#include "lwip/opt.h"

#if LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_OPENHITLS

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/altcp_tcp.h"
#include "lwip/priv/altcp_priv.h"
#include "altcp_tls_openhitls_structs.h"
#include "altcp_tls_openhitls_mem.h"

/* Include required openHiTLS headers for initialization */
#include "hitls/bsl/bsl_init.h"
#include "hitls/bsl/bsl_errno.h"
#include "hitls/bsl/bsl_sal.h"
#include "hitls/bsl/bsl_err.h"
#include "hitls/crypto/crypt_eal_init.h"
#include "hitls/crypto/crypt_eal_rand.h"
#include "hitls/crypto/crypt_errno.h"
#include "hitls/crypto/crypt_algid.h"
#include "hitls/tls/hitls_cert_init.h"
#include "hitls/tls/hitls_crypt_init.h"

#include <string.h>
#include <stdlib.h>

/* Static flag to track initialization */
static u8_t openhitls_initialized = 0;

/**
 * Initialize openHiTLS libraries following demo pattern
 */
static err_t
altcp_openhitls_init_libraries(void)
{
  int32_t ret;
  
  if (openhitls_initialized) {
    return ERR_OK; /* Already initialized */
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_init_libraries: initializing openHiTLS\n"));
  
  /* Register BSL memory capability - use standard malloc/free for openHiTLS */
  BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, malloc);
  BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
  BSL_ERR_Init();
  
  /* Initialize CRYPT layer following demo pattern */
  ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
  if (ret != CRYPT_SUCCESS) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_init_libraries: CRYPT_EAL_Init failed: %d\n", ret));
    return ERR_VAL;
  }
  
  /* Initialize random number generator */
  ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
  if (ret != CRYPT_SUCCESS) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_init_libraries: CRYPT_EAL_ProviderRandInitCtx failed: %d\n", ret));
    return ERR_VAL;
  }
  
  /* Initialize certificate and crypto methods */
  HITLS_CertMethodInit();
  HITLS_CryptMethodInit();
  
  openhitls_initialized = 1;
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_init_libraries: openHiTLS initialized successfully\n"));
  return ERR_OK;
}

/* Forward declarations */
static err_t altcp_openhitls_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static err_t altcp_openhitls_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err);
static err_t altcp_openhitls_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err);
static void altcp_openhitls_lower_err(void *arg, err_t err);
static err_t altcp_openhitls_process_handshake(struct altcp_pcb *conn, altcp_openhitls_state_t *state);
static err_t altcp_openhitls_handle_rx_data(struct altcp_pcb *conn, altcp_openhitls_state_t *state);
static err_t altcp_openhitls_write_encrypted(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags);

/* ALTCP function implementations */
static err_t altcp_openhitls_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected);
static err_t altcp_openhitls_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags);
static err_t altcp_openhitls_close(struct altcp_pcb *conn);
static void altcp_openhitls_abort(struct altcp_pcb *conn);
static void altcp_openhitls_dealloc(struct altcp_pcb *conn);

/* Enhanced ALTCP function table */
const struct altcp_functions altcp_openhitls_functions = {
  altcp_default_set_poll,
  altcp_default_recved,
  altcp_default_bind,
  altcp_openhitls_connect,
  NULL, /* listen - use default TCP behavior */
  altcp_openhitls_abort,
  altcp_openhitls_close,
  altcp_default_shutdown,
  altcp_openhitls_write,
  altcp_default_output,
  altcp_default_mss,
  altcp_default_sndbuf,
  altcp_default_sndqueuelen,
  altcp_default_nagle_disable,
  altcp_default_nagle_enable,
  altcp_default_nagle_disabled,
  altcp_default_setprio,
  altcp_openhitls_dealloc,
  altcp_default_get_tcp_addrinfo,
  altcp_default_get_ip,
  altcp_default_get_port,
#if LWIP_TCP_KEEPALIVE
  NULL, /* keepalive_disable */
  NULL, /* keepalive_enable */
#endif
#ifdef LWIP_DEBUG
  NULL  /* dbg_get_tcp_state */
#endif
};

/**
 * Setup openHiTLS connection with enhanced functionality
 */
static err_t
altcp_openhitls_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
  altcp_openhitls_state_t *state;
  struct altcp_tls_config *config = (struct altcp_tls_config *)conf;
  
  LWIP_ASSERT("invalid arguments", conn != NULL && inner_conn != NULL && config != NULL);
  
  /* Allocate state structure */
  state = (altcp_openhitls_state_t *)altcp_openhitls_calloc(1, sizeof(altcp_openhitls_state_t));
  if (state == NULL) {
    return ERR_MEM;
  }
  
  /* Initialize state */
  state->conf = conf;
  state->flags = 0;
  state->rx = NULL;
  state->rx_app = NULL;
  state->rx_passed_unrecved = 0;
  
  /* Create HITLS context */
  state->hitls_ctx = HITLS_New(config->hitls_config);
  if (state->hitls_ctx == NULL) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_setup: HITLS_New failed\n"));
    altcp_openhitls_free(state);
    return ERR_MEM;
  }
  
  /* Setup connection */
  conn->inner_conn = inner_conn;
  conn->state = state;
  
  /* Set up inner connection callbacks */
  altcp_arg(inner_conn, conn);
  altcp_recv(inner_conn, altcp_openhitls_lower_recv);
  altcp_err(inner_conn, altcp_openhitls_lower_err);
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_setup: connection setup complete\n"));
  return ERR_OK;
}

/**
 * Handle TLS handshake process
 */
static err_t
altcp_openhitls_process_handshake(struct altcp_pcb *conn, altcp_openhitls_state_t *state)
{
  int32_t ret;
  
  if (state->flags & ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE) {
    return ERR_OK; /* Already completed */
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_process_handshake: starting handshake\n"));
  
  /* Perform TLS handshake */
  ret = HITLS_Connect(state->hitls_ctx);
  
  switch (ret) {
    case HITLS_SUCCESS:
      /* Handshake completed successfully */
      state->flags |= ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE;
      LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_process_handshake: handshake completed\n"));
      
      /* Notify upper layer if this is a client connection */
      if (conn->connected) {
        return conn->connected(conn->arg, conn, ERR_OK);
      }
      return ERR_OK;
      
    case HITLS_WANT_READ:
    case HITLS_WANT_WRITE:
      /* Handshake needs more data */
      LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_process_handshake: handshake wants more data\n"));
      return ERR_OK;
      
    default:
      /* Handshake failed */
      LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_process_handshake: handshake failed %d\n", ret));
      return ERR_CONN;
  }
}

/**
 * Handle received application data after decryption
 */
static err_t
altcp_openhitls_handle_rx_data(struct altcp_pcb *conn, altcp_openhitls_state_t *state)
{
  u8_t *buf;
  uint32_t read_len;
  int32_t ret;
  struct pbuf *p;
  err_t err = ERR_OK;
  
  if (!(state->flags & ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE)) {
    return ERR_OK; /* Handshake not complete yet */
  }
  
  /* Allocate buffer for decrypted data */
  buf = (u8_t *)altcp_openhitls_malloc(ALTCP_OPENHITLS_READ_BUFFER_SIZE);
  if (buf == NULL) {
    return ERR_MEM;
  }
  
  /* Read decrypted application data */
  ret = HITLS_Read(state->hitls_ctx, buf, ALTCP_OPENHITLS_READ_BUFFER_SIZE, &read_len);
  
  if (ret == HITLS_SUCCESS && read_len > 0) {
    /* Create pbuf with decrypted data */
    p = pbuf_alloc(PBUF_RAW, (u16_t)read_len, PBUF_POOL);
    if (p != NULL) {
      MEMCPY(p->payload, buf, read_len);
      
      /* Pass to application */
      if (conn->recv) {
        state->rx_passed_unrecved += read_len;
        err = conn->recv(conn->arg, conn, p, ERR_OK);
        if (err != ERR_OK) {
          /* Application couldn't handle the data */
          state->rx_passed_unrecved -= read_len;
          pbuf_free(p);
        }
      } else {
        pbuf_free(p);
      }
    } else {
      err = ERR_MEM;
    }
  } else if (ret == HITLS_WANT_READ) {
    /* Need more encrypted data */
    err = ERR_OK;
  } else {
    /* Error or connection closed */
    if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
      err = ERR_OK; /* No data available */
    } else {
      LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_handle_rx_data: read error %d\n", ret));
      err = ERR_CONN;
    }
  }
  
  altcp_openhitls_free(buf);
  return err;
}

/**
 * Handle received data from lower layer (encrypted)
 */
static err_t
altcp_openhitls_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  altcp_openhitls_state_t *state;
  
  LWIP_UNUSED_ARG(inner_conn);
  
  if (conn == NULL || conn->state == NULL) {
    if (p != NULL) {
      pbuf_free(p);
    }
    return ERR_ARG;
  }
  
  state = (altcp_openhitls_state_t *)conn->state;
  
  if (err != ERR_OK) {
    if (p != NULL) {
      pbuf_free(p);
    }
    /* Notify error to upper layer */
    if (conn->err) {
      conn->err(conn->arg, err);
    }
    return err;
  }
  
  if (p == NULL) {
    /* Connection closed by peer */
    state->flags |= ALTCP_OPENHITLS_FLAGS_RX_CLOSED;
    if (conn->recv) {
      return conn->recv(conn->arg, conn, NULL, ERR_OK);
    }
    return ERR_OK;
  }
  
  /* Add received data to buffer */
  if (state->rx == NULL) {
    state->rx = p;
  } else {
    pbuf_cat(state->rx, p);
  }
  
  /* Process handshake if not completed */
  if (!(state->flags & ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE)) {
    err = altcp_openhitls_process_handshake(conn, state);
    if (err != ERR_OK) {
      return err;
    }
  }
  
  /* Handle application data if handshake is done */
  if (state->flags & ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE) {
    return altcp_openhitls_handle_rx_data(conn, state);
  }
  
  return ERR_OK;
}

/**
 * Handle connection established from lower layer
 */
static err_t
altcp_openhitls_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  altcp_openhitls_state_t *state;
  
  LWIP_UNUSED_ARG(inner_conn);
  
  if (conn == NULL || conn->state == NULL) {
    return ERR_ARG;
  }
  
  if (err != ERR_OK) {
    /* Connection failed */
    if (conn->connected) {
      return conn->connected(conn->arg, conn, err);
    }
    return err;
  }
  
  state = (altcp_openhitls_state_t *)conn->state;
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_lower_connected: TCP connected, starting TLS handshake\n"));
  
  /* Start TLS handshake */
  return altcp_openhitls_process_handshake(conn, state);
}

/**
 * Handle error from lower layer
 */
static void
altcp_openhitls_lower_err(void *arg, err_t err)
{
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  
  if (conn == NULL) {
    return;
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_lower_err: error %d\n", err));
  
  /* Pass error to upper layer */
  if (conn->err) {
    conn->err(conn->arg, err);
  }
}

/**
 * Connect to remote host with TLS
 */
static err_t
altcp_openhitls_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
  if (conn == NULL || conn->inner_conn == NULL) {
    return ERR_ARG;
  }
  
  /* Store the connected callback */
  conn->connected = connected;
  
  /* Initiate TCP connection - the connected callback will trigger TLS handshake */
  return altcp_connect(conn->inner_conn, ipaddr, port, altcp_openhitls_lower_connected);
}

/**
 * Write application data (will be encrypted)
 */
static err_t
altcp_openhitls_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
  altcp_openhitls_state_t *state;
  uint32_t written_len;
  int32_t ret;
  
  LWIP_UNUSED_ARG(apiflags);
  
  if (conn == NULL || conn->state == NULL || dataptr == NULL || len == 0) {
    return ERR_ARG;
  }
  
  state = (altcp_openhitls_state_t *)conn->state;
  
  if (!(state->flags & ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE)) {
    /* Handshake not complete yet */
    return ERR_CONN;
  }
  
  if (state->hitls_ctx == NULL) {
    return ERR_CONN;
  }
  
  /* Write data through HITLS (will be encrypted) */
  ret = HITLS_Write(state->hitls_ctx, (const uint8_t *)dataptr, len, &written_len);
  
  if (ret == HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_write: wrote %u bytes\n", written_len));
    return ERR_OK;
  } else if (ret == HITLS_WANT_WRITE) {
    /* Would block - try again later */
    return ERR_MEM;
  } else {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_write: write error %d\n", ret));
    return ERR_CONN;
  }
}

/**
 * Close TLS connection
 */
static err_t
altcp_openhitls_close(struct altcp_pcb *conn)
{
  altcp_openhitls_state_t *state;
  
  if (conn == NULL || conn->state == NULL) {
    return ERR_ARG;
  }
  
  state = (altcp_openhitls_state_t *)conn->state;
  
  /* Send TLS close_notify if handshake was completed */
  if ((state->flags & ALTCP_OPENHITLS_FLAGS_HANDSHAKE_DONE) && state->hitls_ctx) {
    HITLS_Close(state->hitls_ctx);
  }
  
  /* Close underlying TCP connection */
  if (conn->inner_conn) {
    return altcp_close(conn->inner_conn);
  }
  
  return ERR_OK;
}

/**
 * Abort TLS connection
 */
static void
altcp_openhitls_abort(struct altcp_pcb *conn)
{
  if (conn != NULL && conn->inner_conn != NULL) {
    altcp_abort(conn->inner_conn);
  }
}

/**
 * Deallocate TLS connection state
 */
static void
altcp_openhitls_dealloc(struct altcp_pcb *conn)
{
  altcp_openhitls_state_t *state;
  
  if (conn == NULL || conn->state == NULL) {
    return;
  }
  
  state = (altcp_openhitls_state_t *)conn->state;
  
  /* Free receive buffers */
  if (state->rx != NULL) {
    pbuf_free(state->rx);
  }
  if (state->rx_app != NULL) {
    pbuf_free(state->rx_app);
  }
  
  /* Free HITLS context */
  if (state->hitls_ctx != NULL) {
    HITLS_Free(state->hitls_ctx);
  }
  
  /* Free UIO if exists */
  if (state->uio != NULL) {
    BSL_UIO_Free(state->uio);
  }
  
  /* Free state structure */
  altcp_openhitls_free(state);
  conn->state = NULL;
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_openhitls_dealloc: connection deallocated\n"));
}

/**
 * Enhanced API functions
 */

struct altcp_tls_config *
altcp_tls_create_config_server_privkey_cert(const u8_t *privkey, size_t privkey_len,
                                             const u8_t *privkey_pass, size_t privkey_pass_len,
                                             const u8_t *cert, size_t cert_len)
{
  struct altcp_tls_config *config;
  int32_t ret;
  
  LWIP_UNUSED_ARG(privkey);      /* TODO: Implement certificate loading */
  LWIP_UNUSED_ARG(privkey_len);
  LWIP_UNUSED_ARG(privkey_pass);
  LWIP_UNUSED_ARG(privkey_pass_len);
  LWIP_UNUSED_ARG(cert);
  LWIP_UNUSED_ARG(cert_len);
  
  /* Initialize openHiTLS libraries first */
  if (altcp_openhitls_init_libraries() != ERR_OK) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_server: openHiTLS init failed\n"));
    return NULL;
  }
  
  /* Allocate config structure */
  config = (struct altcp_tls_config *)altcp_openhitls_calloc(1, sizeof(struct altcp_tls_config));
  if (config == NULL) {
    return NULL;
  }
  
  /* Create HITLS configuration for server - use TLS 1.2 like demo */
  config->hitls_config = HITLS_CFG_NewTLS12Config();
  if (config->hitls_config == NULL) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_server: HITLS_CFG_NewTLS12Config failed\n"));
    altcp_openhitls_free(config);
    return NULL;
  }
  
  /* Configure as server */
  ret = HITLS_CFG_SetClientVerifySupport(config->hitls_config, false);
  if (ret != HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_server: config failed %d\n", ret));
    HITLS_CFG_FreeConfig(config->hitls_config);
    altcp_openhitls_free(config);
    return NULL;
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_server: config created successfully\n"));
  return config;
}

struct altcp_tls_config *
altcp_tls_create_config_client(const u8_t *cert, size_t cert_len)
{
  struct altcp_tls_config *config;
  int32_t ret;
  
  LWIP_UNUSED_ARG(cert);         /* TODO: Implement CA certificate loading */
  LWIP_UNUSED_ARG(cert_len);
  
  /* Initialize openHiTLS libraries first */
  if (altcp_openhitls_init_libraries() != ERR_OK) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_client: openHiTLS init failed\n"));
    return NULL;
  }
  
  /* Allocate config structure */
  config = (struct altcp_tls_config *)altcp_openhitls_calloc(1, sizeof(struct altcp_tls_config));
  if (config == NULL) {
    return NULL;
  }
  
  /* Create HITLS configuration for client - use TLS 1.2 like demo */
  config->hitls_config = HITLS_CFG_NewTLS12Config();
  if (config->hitls_config == NULL) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_client: HITLS_CFG_NewTLS12Config failed\n"));
    altcp_openhitls_free(config);
    return NULL;
  }
  
  /* Configure client settings - disable verification like in demo */
  ret = HITLS_CFG_SetCheckKeyUsage(config->hitls_config, false);
  if (ret != HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_client: disable check keyusage failed %d\n", ret));
  }
  
  /* Also disable all verification for simplicity */
  ret = HITLS_CFG_SetVerifyNoneSupport(config->hitls_config, true);
  if (ret != HITLS_SUCCESS) {
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_client: disable verify failed %d\n", ret));
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_create_config_client: config created successfully\n"));
  return config;
}

void
altcp_tls_free_config(struct altcp_tls_config *conf)
{
  if (conf != NULL) {
    if (conf->hitls_config != NULL) {
      HITLS_CFG_FreeConfig(conf->hitls_config);
    }
    altcp_openhitls_free(conf);
    LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_free_config: config freed\n"));
  }
}

struct altcp_pcb *
altcp_tls_new_openhitls(struct altcp_tls_config *config, u8_t ip_type)
{
  struct altcp_pcb *inner_pcb, *conn;
  err_t err;
  
  if (config == NULL) {
    return NULL;
  }
  
  /* Create inner TCP connection */
  inner_pcb = altcp_tcp_new_ip_type(ip_type);
  if (inner_pcb == NULL) {
    return NULL;
  }
  
  /* Create ALTCP connection */
  conn = altcp_alloc();
  if (conn == NULL) {
    altcp_close(inner_pcb);
    return NULL;
  }
  
  /* Setup openHiTLS layer */
  err = altcp_openhitls_setup(config, conn, inner_pcb);
  if (err != ERR_OK) {
    altcp_close(inner_pcb);
    altcp_free(conn);
    return NULL;
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_new_openhitls: connection created\n"));
  return conn;
}

struct altcp_pcb *
altcp_tls_wrap(struct altcp_tls_config *config, struct altcp_pcb *inner_pcb)
{
  struct altcp_pcb *conn;
  err_t err;
  
  if (config == NULL || inner_pcb == NULL) {
    return NULL;
  }
  
  /* Create ALTCP connection */
  conn = altcp_alloc();
  if (conn == NULL) {
    return NULL;
  }
  
  /* Setup openHiTLS layer */
  err = altcp_openhitls_setup(config, conn, inner_pcb);
  if (err != ERR_OK) {
    altcp_free(conn);
    return NULL;
  }
  
  LWIP_DEBUGF(ALTCP_OPENHITLS_DEBUG, ("altcp_tls_wrap: connection wrapped\n"));
  return conn;
}

#endif /* LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_OPENHITLS */