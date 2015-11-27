#include "ucspissl.h"

int ssl_params(SSL_CTX *ctx,const char *dhfile,int rsalen, int eclen)
{
  DH *dh;
  RSA *rsa;
  BIO *bio;
  EC_KEY *ecdh;

  if (dhfile) {
    bio = BIO_new_file(dhfile,"r");
    if (!bio) return 0;
    dh = PEM_read_bio_DHparams(bio,0,0,0);
    BIO_free(bio);
    if (!dh) return 0;
  }

  if (rsalen) {
    rsa = RSA_generate_key(rsalen,RSA_F4,0,0);
    if (!rsa) return 0;
  }

  if (eclen) {
    switch (eclen) {
      case 163:
        ecdh = EC_KEY_new_by_curve_name(OBJ_sn2nid("sect163r2"));
        break;
      case 193:
        ecdh = EC_KEY_new_by_curve_name(OBJ_sn2nid("sect193r2"));
        break;
      case 256:
        ecdh = EC_KEY_new_by_curve_name(OBJ_sn2nid("secp256k1"));
        break;
      case 283:
        ecdh = EC_KEY_new_by_curve_name(OBJ_sn2nid("sect283k1"));
        break;
      case 409:
        ecdh = EC_KEY_new_by_curve_name(OBJ_sn2nid("sect409k1"));
        break;
      case 571:
        ecdh = EC_KEY_new_by_curve_name(OBJ_sn2nid("sect571k1"));
        break;
      default:
        return 0;
    }

    if (!ecdh) return 0;
    EC_KEY_free(ecdh);
  }

  return 1;
}

