#include "ucspissl.h"

int ssl_certkey(SSL_CTX *ctx,const char *certfile, const char *certfileec,
                const char *keyfile, const char *keyfileec, pem_password_cb *passwd_cb)
{
  if (!certfile) return 0;

  SSL_CTX_set_default_passwd_cb(ctx,passwd_cb);

  if (SSL_CTX_use_certificate_chain_file(ctx,certfile) != 1)
    return -1;
  if (keyfile) {
    if (SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM) != 1)
      return -2;
  }

  if (SSL_CTX_use_certificate_chain_file(ctx,certfileec) != 1)
    return -3;
  if (keyfileec) {
    if (SSL_CTX_use_PrivateKey_file(ctx,keyfileec,SSL_FILETYPE_PEM) != 1)
      return -4;
  }

  if (SSL_CTX_check_private_key(ctx) != 1)
    return -5;

  return 0;
}

