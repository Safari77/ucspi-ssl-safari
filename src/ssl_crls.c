#include <sys/types.h>
#include <dirent.h>
#include "stralloc.h"
#include "str.h"
#include "case.h"
#include "ucspissl.h"

int ssl_crls(SSL_CTX *ctx, const char *crldir)
{
  X509_STORE *store;
  X509_LOOKUP *x509lookup;
  DIR *dip;
  struct dirent *dire;
  static stralloc dirstr = {0};

  if (!crldir) return 1;
  dip = opendir(crldir);
  if (!dip) return 0;

  store = SSL_CTX_get_cert_store(ctx);
  x509lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  if (x509lookup) {
    const char *fn;
    int fnlen;
    int ok = 0;

    while ((dire = readdir(dip))) {
      fn = dire->d_name;
      fnlen = str_len(fn);
 
      if (!stralloc_copys(&dirstr, crldir)) return 0;
      if (!stralloc_cats(&dirstr, "/")) return 0;
      if (!stralloc_cats(&dirstr, fn)) return 0;
      if (!stralloc_0(&dirstr)) return 0;
      if ((fnlen > 4) && (!case_diffb(fn+fnlen-4, 4, ".pem"))) {
        if (X509_load_crl_file(x509lookup, dirstr.s, X509_FILETYPE_PEM) == 1) ok++;
      }
    }
    closedir(dip);
    if (ok > 0) {
      X509_STORE_set_flags(store, (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) );
      return 1;
    }
  }
  closedir(dip);
  return 0;
}

