#include "ucspissl.h"

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
  return 1;
}

int ssl_ca(SSL_CTX *ctx,const char *certfile,const char *certdir,int d, int vfy)
{
  if (!SSL_CTX_load_verify_locations(ctx,certfile,certdir)) return 0;

  SSL_CTX_set_verify_depth(ctx,d);

  if (vfy) {
    SSL_CTX_set_verify(ctx, (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE), verify_cb);
  }

  return 1;
}

