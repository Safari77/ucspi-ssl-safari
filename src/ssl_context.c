#include "ucspissl.h"

#ifndef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
#  define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (0)
#endif

#ifndef SSL_OP_NO_COMPRESSION
#  define SSL_OP_NO_COMPRESSION (0)
#endif

SSL_CTX *ssl_context(const SSL_METHOD *m)
{
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(m);
  if (ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                     SSL_MODE_ENABLE_PARTIAL_WRITE);
  }

  return ctx;
}

