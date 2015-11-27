#include <unistd.h>
#include "fmt.h"
#include "pathexec.h"
#include "stralloc.h"
#include "str.h"
#include "ucspissl.h"

static char strnum[FMT_ULONG];
static stralloc ctemp = {0};
static stralloc *envsa = 0;
static stralloc btemp = {0};
static stralloc etemp = {0};

#ifndef NID_x500UniqueIdentifier
#define NID_x500UniqueIdentifier NID_uniqueIdentifier
#endif

#define set_env_id(n,e,v) \
if (!set_env_name_entry((n),(e),(v))) return 0

static int env_val(const char *env,const char *val,int len) {
  if (envsa) {
    if (!stralloc_cats(envsa,env)) return 0;
    if (!stralloc_catb(envsa,"=",1)) return 0;
    if (!stralloc_catb(envsa,val,len)) return 0;
    if (!stralloc_0(envsa)) return 0;
    return 1;
  }
  if (!stralloc_copyb(&etemp,val,len)) return 0;
  if (!stralloc_0(&etemp)) return 0;
  return pathexec_env(env,etemp.s);
}

static int env_str(const char *env,const char *val) {
  if (envsa) {
    return env_val(env,val,str_len(val));
    if (!stralloc_cats(envsa,env)) return 0;
    if (!stralloc_catb(envsa,"=",1)) return 0;
    if (!stralloc_catb(envsa,val,str_len(val) + 1)) return 0;
    return 1;
  }
  return pathexec_env(env,val);
}

static int set_env_name_entry(X509_NAME *xname,const char *env,int nid) {
  int m;
  int n;
  X509_NAME_ENTRY *xne;

  if (!env) return 1;
  for (m = 0;m < sk_X509_NAME_ENTRY_num(xname->entries);m++) {
    xne = sk_X509_NAME_ENTRY_value(xname->entries,m);
    n = OBJ_obj2nid(xne->object);
    if (n == nid)
      if (!env_val(env,xne->value->data,xne->value->length)) return 0;
  }
  return 1;
}

int ssl_session_vars(SSL *ssl) {
  char *x;
  SSL_SESSION *session;
  int n;
  int m;
  SSL_CIPHER *cipher;
  unsigned char u;
  unsigned char c;
  const char *vfystring;
  X509 *cert;
  X509_STORE *store;
  X509_STORE_CTX store_ctx;
  int storeok = 0;
  int x509ret = 0;
  EVP_PKEY *pktmp;

  if (!env_str("SSL_PROTOCOL",SSL_get_version(ssl)))
    return 0;

  if (!ssl->ctx)
    return 0;
  store = SSL_CTX_get_cert_store(ssl->ctx); 
  cert = SSL_get_peer_certificate(ssl);
  if (cert) {
    if (X509_STORE_CTX_init(&store_ctx, store, cert, NULL) != 1) {
      X509_free(cert);
      return 0;
    }
    pktmp = X509_get_pubkey(cert);
    if (!env_val("SSL_PUBKEY_SIZE", strnum,
        fmt_ulong(strnum,EVP_PKEY_bits(pktmp)))) return 0;
    EVP_PKEY_free(pktmp);
    X509_STORE_CTX_set_cert(&store_ctx, cert);
    storeok = X509_verify_cert(&store_ctx);
    x509ret = X509_STORE_CTX_get_error(&store_ctx);
    X509_STORE_CTX_cleanup(&store_ctx);
    X509_free(cert);
    vfystring = X509_verify_cert_error_string(x509ret);
    if (!env_str("SSL_VERIFY_STRING",vfystring)) return 0;
    if ((x509ret == X509_V_OK) && (storeok == 1)) {
      if (!env_str("SSL_VERIFY_STATUS","OK")) return 0;
    } else {
      if (!env_str("SSL_VERIFY_STATUS","FAIL")) return 0;
    }
  } else {
   if (!env_str("SSL_VERIFY_STRING","FAIL")) return 0;
   if (!env_str("SSL_VERIFY_STATUS","NOCERT")) return 0;
  }
  session = SSL_get_session(ssl);
  x = session->session_id;
  n = session->session_id_length;
  if (!stralloc_ready(&btemp,2 * n)) return 0;
  btemp.len = 2 * n;
  while (n--) {
    u = x[n];
    c = '0' + (u & 15); if (c > '0' + 9) c += 'a' - '0' - 10;
    btemp.s[2 * n + 1] = c;
    u >>= 4;
    c = '0' + (u & 15); if (c > '0' + 9) c += 'a' - '0' - 10;
    btemp.s[2 * n] = c;
  }
  if (!env_val("SSL_SESSION_ID",btemp.s,btemp.len)) return 0;

  cipher = SSL_get_current_cipher(ssl);
  if (!cipher) return 0;
  if (!env_str("SSL_CIPHER",SSL_CIPHER_get_name(cipher))) return 0;

  n = SSL_CIPHER_get_bits(cipher,&m);
  if (!env_str("SSL_CIPHER_EXPORT",n < 56 ? "true" : "false")) return 0;
  if (!env_val("SSL_CIPHER_USEKEYSIZE",strnum,fmt_ulong(strnum,n))) return 0;
  if (!env_val("SSL_CIPHER_ALGKEYSIZE",strnum,fmt_ulong(strnum,m))) return 0;

  if (!env_val("SSL_RFD",strnum,fmt_ulong(strnum,SSL_get_rfd(ssl)))) return 0;
  if (!env_val("SSL_WFD",strnum,fmt_ulong(strnum,SSL_get_wfd(ssl)))) return 0;
  if (!env_str("SSL_VERSION_INTERFACE","ucspi-ssl")) return 0;
  if (!env_str("SSL_VERSION_LIBRARY",OPENSSL_VERSION_TEXT)) return 0;

  return 1;
}

static int ssl_client_bio_vars(X509 *cert,STACK_OF(X509) *chain,BIO *bio) {
  int n;
  int m;
  ASN1_STRING *astring;

  astring = X509_get_notBefore(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_CLIENT_V_START",btemp.s,btemp.len)) return 0;

  astring = X509_get_notAfter(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_CLIENT_V_END",btemp.s,btemp.len)) return 0;

  if (!PEM_write_bio_X509(bio,cert)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_CLIENT_CERT",btemp.s,btemp.len)) return 0;

  if (chain) {
    for (m = 0;m < sk_X509_num(chain);m++) {
      if (!stralloc_copys(&ctemp,"SSL_CLIENT_CERT_CHAIN_")) return 0;
      if (!stralloc_catb(&ctemp,strnum,fmt_ulong(strnum,m))) return 0;
      if (!stralloc_0(&ctemp)) return 0;

      if (m < sk_X509_num(chain)) {
	if (!PEM_write_bio_X509(bio,sk_X509_value(chain,m))) return 0;
	n = BIO_pending(bio);
	if (!stralloc_ready(&btemp,n)) return 0;
	btemp.len = n;
	n = BIO_read(bio,btemp.s,n);
	if (n != btemp.len) return 0;
	if (!env_val(ctemp.s,btemp.s,btemp.len)) return 0;
      }
    }
  }

  return 1;
}

static const unsigned char hextbl[] = "0123456789abcdef";

static char *x509digest_sha1(X509* peer)
{
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen, i;
  static unsigned char nibbles[EVP_MAX_MD_SIZE*2+1];
  const EVP_MD *edg = EVP_sha1();

  if (!X509_digest(peer, edg, md, &mdlen)) return NULL; 
  for (i = 0; i < mdlen; i++) {
    nibbles[i*2+0] = hextbl[(md[i] >> 4)];
    nibbles[i*2+1] = hextbl[(md[i] & 15)];
  }
  nibbles[i*2] = 0;
  return nibbles;
}

static char *x509digest_sha256(X509* peer)
{
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen, i;
  static unsigned char nibbles[EVP_MAX_MD_SIZE*2+1];
  const EVP_MD *edg = EVP_sha256();

  if (!X509_digest(peer, edg, md, &mdlen)) return NULL; 
  for (i = 0; i < mdlen; i++) {
    nibbles[i*2+0] = hextbl[(md[i] >> 4)];
    nibbles[i*2+1] = hextbl[(md[i] & 15)];
  }
  nibbles[i*2] = 0;
  return nibbles;
}

static int ssl_client_vars(X509 *cert,STACK_OF(X509) *chain) {
  X509_NAME *xname;
  char *x;
  int n;
  BIGNUM *bn;
  BIO *bio;

  if (!cert) return 1;

  if (!env_val("SSL_CLIENT_M_VERSION",strnum,fmt_ulong(strnum,X509_get_version(cert) + 1)))
    return 0;

  bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), 0);
  x = BN_bn2dec(bn);
  BN_free(bn);
  if (!env_val("SSL_CLIENT_M_SERIAL",x,strlen(x)))
     return 0;
  OPENSSL_free(x);

  xname = X509_get_subject_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_CLIENT_S_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_CLIENT_S_DN_C",NID_countryName);
  set_env_id(xname,"SSL_CLIENT_S_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_CLIENT_S_DN_L",NID_localityName);
  set_env_id(xname,"SSL_CLIENT_S_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_CLIENT_S_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_CLIENT_S_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_CLIENT_S_DN_T",NID_title);
  set_env_id(xname,"SSL_CLIENT_S_DN_I",NID_initials);
  set_env_id(xname,"SSL_CLIENT_S_DN_G",NID_givenName);
  set_env_id(xname,"SSL_CLIENT_S_DN_S",NID_surname);
  set_env_id(xname,"SSL_CLIENT_S_DN_D",NID_description);
#if OPENSSL_VERSION_NUMBER >= 0x00907000
  set_env_id(xname,"SSL_CLIENT_S_DN_UID",NID_x500UniqueIdentifier);
#else
  set_env_id(xname,"SSL_CLIENT_S_DN_UID",NID_uniqueIdentifier);
#endif
  set_env_id(xname,"SSL_CLIENT_S_DN_Email",NID_pkcs9_emailAddress);

  xname = X509_get_issuer_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_CLIENT_I_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_CLIENT_I_DN_C",NID_countryName);
  set_env_id(xname,"SSL_CLIENT_I_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_CLIENT_I_DN_L",NID_localityName);
  set_env_id(xname,"SSL_CLIENT_I_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_CLIENT_I_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_CLIENT_I_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_CLIENT_I_DN_T",NID_title);
  set_env_id(xname,"SSL_CLIENT_I_DN_I",NID_initials);
  set_env_id(xname,"SSL_CLIENT_I_DN_G",NID_givenName);
  set_env_id(xname,"SSL_CLIENT_I_DN_S",NID_surname);
  set_env_id(xname,"SSL_CLIENT_I_DN_D",NID_description);
#if OPENSSL_VERSION_NUMBER < 0x0090700fL
  set_env_id(xname,"SSL_CLIENT_I_DN_UID",NID_uniqueIdentifier);
#else
  set_env_id(xname,"SSL_CLIENT_I_DN_UID",NID_x500UniqueIdentifier);
#endif
  set_env_id(xname,"SSL_CLIENT_I_DN_Email",NID_pkcs9_emailAddress);

  n = OBJ_obj2nid(cert->cert_info->signature->algorithm);
  if (!env_str("SSL_CLIENT_A_SIG",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  n = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (!env_str("SSL_CLIENT_A_KEY",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  x = x509digest_sha1(cert);
  if (!x) return 0;
  if (!env_str("SSL_CLIENT_DIGEST_SHA1", x)) return 0;

  x = x509digest_sha256(cert);
  if (!x) return 0;
  if (!env_str("SSL_CLIENT_DIGEST_SHA256", x)) return 0;

  bio = BIO_new(BIO_s_mem());
  if (!bio) return 0;
  n = ssl_client_bio_vars(cert,chain,bio);
  BIO_free(bio);
  if (!n) return 0;

  return 1;
}

static int ssl_server_bio_vars(X509 *cert,STACK_OF(X509) *chain,BIO *bio) {
  int n;
  int m;
  ASN1_STRING *astring;

  astring = X509_get_notBefore(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_SERVER_V_START",btemp.s,btemp.len)) return 0;

  astring = X509_get_notAfter(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_SERVER_V_END",btemp.s,btemp.len)) return 0;


  if (!PEM_write_bio_X509(bio,cert)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_SERVER_CERT",btemp.s,btemp.len)) return 0;

  if (chain) {
    for (m = 0;m < sk_X509_num(chain);m++) {
      if (!stralloc_copys(&ctemp,"SSL_SERVER_CERT_CHAIN_")) return 0;
      if (!stralloc_catb(&ctemp,strnum,fmt_ulong(strnum,m))) return 0;
      if (!stralloc_0(&ctemp)) return 0;

      if (m < sk_X509_num(chain)) {
	if (!PEM_write_bio_X509(bio,sk_X509_value(chain,m))) return 0;
	n = BIO_pending(bio);
	if (!stralloc_ready(&btemp,n)) return 0;
	btemp.len = n;
	n = BIO_read(bio,btemp.s,n);
	if (n != btemp.len) return 0;
	if (!env_val(ctemp.s,btemp.s,btemp.len)) return 0;
      }
    }
  }

  return 1;
}

static int ssl_server_vars(X509 *cert,STACK_OF(X509) *chain) {
  X509_NAME *xname;
  char *x;
  int n;
  BIGNUM *bn;
  BIO *bio;

  if (!cert) return 1;

  if (!env_val("SSL_SERVER_M_VERSION",strnum,fmt_ulong(strnum,X509_get_version(cert) + 1)))
    return 0;

  bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), 0);
  x = BN_bn2dec(bn);
  BN_free(bn);
  if (!env_val("SSL_SERVER_M_SERIAL",x,strlen(x)))
    return 0;
  OPENSSL_free(x); 

  xname = X509_get_subject_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_SERVER_S_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_SERVER_S_DN_C",NID_countryName);
  set_env_id(xname,"SSL_SERVER_S_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_SERVER_S_DN_L",NID_localityName);
  set_env_id(xname,"SSL_SERVER_S_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_SERVER_S_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_SERVER_S_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_SERVER_S_DN_T",NID_title);
  set_env_id(xname,"SSL_SERVER_S_DN_I",NID_initials);
  set_env_id(xname,"SSL_SERVER_S_DN_G",NID_givenName);
  set_env_id(xname,"SSL_SERVER_S_DN_S",NID_surname);
  set_env_id(xname,"SSL_SERVER_S_DN_D",NID_description);
  set_env_id(xname,"SSL_SERVER_S_DN_UID",NID_x500UniqueIdentifier);
  set_env_id(xname,"SSL_SERVER_S_DN_Email",NID_pkcs9_emailAddress);

  xname = X509_get_issuer_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_SERVER_I_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_SERVER_I_DN_C",NID_countryName);
  set_env_id(xname,"SSL_SERVER_I_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_SERVER_I_DN_L",NID_localityName);
  set_env_id(xname,"SSL_SERVER_I_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_SERVER_I_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_SERVER_I_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_SERVER_I_DN_T",NID_title);
  set_env_id(xname,"SSL_SERVER_I_DN_I",NID_initials);
  set_env_id(xname,"SSL_SERVER_I_DN_G",NID_givenName);
  set_env_id(xname,"SSL_SERVER_I_DN_S",NID_surname);
  set_env_id(xname,"SSL_SERVER_I_DN_D",NID_description);
  set_env_id(xname,"SSL_SERVER_I_DN_UID",NID_x500UniqueIdentifier);
  set_env_id(xname,"SSL_SERVER_I_DN_Email",NID_pkcs9_emailAddress);

  n = OBJ_obj2nid(cert->cert_info->signature->algorithm);
  if (!env_str("SSL_SERVER_A_SIG",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  n = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (!env_str("SSL_SERVER_A_KEY",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  x = x509digest_sha1(cert);
  if (!x) return 0;
  if (!env_str("SSL_SERVER_DIGEST_SHA1", x)) return 0;

  x = x509digest_sha256(cert);
  if (!x) return 0;
  if (!env_str("SSL_SERVER_DIGEST_SHA256", x)) return 0;

  bio = BIO_new(BIO_s_mem());
  if (!bio) return 0;
  n = ssl_server_bio_vars(cert,chain,bio);
  BIO_free(bio);
  if (!n) return 0;

  return 1;
}

int ssl_client_env(SSL *ssl,stralloc *sa) {
  X509 *cert;

  envsa = sa;
  if (!ssl_session_vars(ssl)) return 0;
  if (!ssl_client_vars(SSL_get_certificate(ssl),0))
    return 0;
  cert = SSL_get_peer_certificate(ssl);
  if (!ssl_server_vars(cert,SSL_get_peer_cert_chain(ssl))) {
    X509_free(cert);
    return 0;
  }
  X509_free(cert);
  return 1;
}

int ssl_server_env(SSL *ssl,stralloc *sa) {
  X509 *cert;

  envsa = sa;
  if (!ssl_session_vars(ssl)) return 0;
  if (!ssl_server_vars(SSL_get_certificate(ssl),0))
    return 0;
  cert = SSL_get_peer_certificate(ssl);
  if (!ssl_client_vars(cert,SSL_get_peer_cert_chain(ssl))) {
    X509_free(cert);
    return 0;
   }
  return 1;
}


