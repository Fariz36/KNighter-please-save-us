## Patch Description

ossl_verifyhost: remove assumption of null termination of ASN1_STRING.

This only affects hosts where the deprecated CN is used for matching DNS
names, instead of the modern way, which is by using a dNSName-typed SAN.

A similar change but for certs that store the hostname in the SAN (as
they should nowadays) was in 543adc4de024dda4f3b8f368893c7d01a3cf0ea8.

Fixes #22822
Closes #22824

## Buggy Code

```c
// Function: ossl_verifyhost in lib/vtls/openssl.c
static CURLcode ossl_verifyhost(struct Curl_easy *data,
                                struct connectdata *conn,
                                struct ssl_peer *peer,
                                X509 *server_cert)
{
  bool matched = FALSE;
  int target; /* target type, GEN_DNS or GEN_IPADD */
  size_t addrlen = 0;
  STACK_OF(GENERAL_NAME) *altnames;
#ifdef USE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
  CURLcode result = CURLE_OK;
  bool dNSName = FALSE; /* if a dNSName field exists in the cert */
  bool iPAddress = FALSE; /* if an iPAddress field exists in the cert */
  size_t hostlen = strlen(peer->origin->hostname);

  (void)conn;
  switch(peer->type) {
  case CURL_SSL_PEER_IPV4:
    if(!curlx_inet_pton(AF_INET, peer->origin->hostname, &addr))
      return CURLE_PEER_FAILED_VERIFICATION;
    target = GEN_IPADD;
    addrlen = sizeof(struct in_addr);
    break;
#ifdef USE_IPV6
  case CURL_SSL_PEER_IPV6:
    if(!curlx_inet_pton(AF_INET6, peer->origin->hostname, &addr))
      return CURLE_PEER_FAILED_VERIFICATION;
    target = GEN_IPADD;
    addrlen = sizeof(struct in6_addr);
    break;
#endif
  case CURL_SSL_PEER_DNS:
    target = GEN_DNS;
    break;
  default:
    DEBUGASSERT(0);
    failf(data, "unexpected SSL peer type: %d", (int)peer->type);
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  /* get a "list" of alternative names */
  altnames = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);

  if(altnames) {
#ifdef HAVE_BORINGSSL_LIKE
    size_t numalts;
    size_t i;
#else
    int numalts;
    int i;
#endif

    /* get amount of alternatives, RFC2459 claims there MUST be at least
       one, but we do not depend on it... */
    numalts = sk_GENERAL_NAME_num(altnames);

    /* loop through all alternatives - until a dnsmatch */
    for(i = 0; (i < numalts) && !matched; i++) {
      /* get a handle to alternative name number i */
      const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);

      if(check->type == GEN_DNS)
        dNSName = TRUE;
      else if(check->type == GEN_IPADD)
        iPAddress = TRUE;

      /* only check alternatives of the same type the target is */
      if(check->type == target) {
        /* get data and length */
        const char *altptr = (const char *)ASN1_STRING_get0_data(check->d.ia5);
        size_t altlen = (size_t)ASN1_STRING_length(check->d.ia5);

        switch(target) {
        case GEN_DNS: /* name/pattern comparison */
          if(!memchr(altptr, '\0', altlen) &&
             Curl_cert_hostcheck(altptr, altlen,
                                 peer->origin->hostname, hostlen)) {
            matched = TRUE;
            infof(data, "  subjectAltName: \"%s\" matches cert's \"%.*s\"",
                  peer->origin->user_hostname, (int)altlen, altptr);
          }
          break;

        case GEN_IPADD: /* IP address comparison */
          /* compare alternative IP address if the data chunk is the same size
             our server IP address is */
          if((altlen == addrlen) && !memcmp(altptr, &addr, altlen)) {
            matched = TRUE;
            infof(data, "  subjectAltName: \"%s\" matches cert's IP address!",
                  peer->origin->user_hostname);
          }
          break;
        }
      }
    }
    GENERAL_NAMES_free(altnames);
  }

  if(matched)
    /* an alternative name matched */
    ;
  else if(dNSName || iPAddress) {
    const char *tname = (peer->type == CURL_SSL_PEER_DNS) ? "hostname" :
                        (peer->type == CURL_SSL_PEER_IPV4) ?
                        "IPv4 address" : "IPv6 address";
    infof(data, " subjectAltName does not match %s %s", tname,
          peer->origin->user_hostname);
    failf(data, "SSL: no alternative certificate subject name matches "
          "target %s '%s'", tname, peer->origin->user_hostname);
    result = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    /* we have to look to the last occurrence of a commonName in the
       distinguished one to get the most significant one. */
    int i = -1;
    unsigned char *cn = NULL;
    int cnlen = 0;
    bool free_cn = FALSE;

    /* The following is done because of a bug in 0.9.6b */
    const X509_NAME *name = X509_get_subject_name(server_cert);
    if(name) {
      int j;
      while((j = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
        i = j;
    }

    /* we have the name entry and we now convert this to a string
       that we can use for comparison. Doing this we support BMPstring,
       UTF8, etc. */

    if(i >= 0) {
      const ASN1_STRING *tmp =
        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

      /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
         is already UTF-8 encoded. We check for this case and copy the raw
         string manually to avoid the problem. This code can be made
         conditional in the future when OpenSSL has been fixed. */
      if(tmp) {
        if(ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
          cnlen = ASN1_STRING_length(tmp);
          cn = (unsigned char *)CURL_UNCONST(ASN1_STRING_get0_data(tmp));
        }
        else { /* not a UTF8 name */
          cnlen = ASN1_STRING_to_UTF8(&cn, tmp);
          free_cn = TRUE;
        }

        if((cnlen <= 0) || !cn)
          result = CURLE_OUT_OF_MEMORY;
        else if((size_t)cnlen != strlen((char *)cn)) {
          /* there was a null-terminator before the end of string, this
             cannot match and we return failure! */
          failf(data, "SSL: illegal cert name field");
          result = CURLE_PEER_FAILED_VERIFICATION;
        }
      }
    }

    if(result)
      /* error already detected, pass through */
      ;
    else if(!cn) {
      failf(data, "SSL: unable to obtain common name from peer certificate");
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else if(!Curl_cert_hostcheck((const char *)cn, cnlen,
                                 peer->origin->hostname, hostlen)) {
      failf(data, "SSL: certificate subject name '%s' does not match "
            "target hostname '%s'", cn, peer->origin->user_hostname);
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else {
      infof(data, " common name: %s (matched)", cn);
    }
    if(free_cn)
      OPENSSL_free(cn);
  }

  return result;
}
```

## Bug Fix Patch

```diff
diff --git a/lib/vtls/openssl.c b/lib/vtls/openssl.c
index 145d228dd5..d43f1bdc9b 100644
--- a/lib/vtls/openssl.c
+++ b/lib/vtls/openssl.c
@@ -2166,7 +2166,7 @@ static CURLcode ossl_verifyhost(struct Curl_easy *data,
 
         if((cnlen <= 0) || !cn)
           result = CURLE_OUT_OF_MEMORY;
-        else if((size_t)cnlen != strlen((char *)cn)) {
+        else if(memchr(cn, '\0', cnlen)) {
           /* there was a null-terminator before the end of string, this
              cannot match and we return failure! */
           failf(data, "SSL: illegal cert name field");
@@ -2184,12 +2184,12 @@ static CURLcode ossl_verifyhost(struct Curl_easy *data,
     }
     else if(!Curl_cert_hostcheck((const char *)cn, cnlen,
                                  peer->origin->hostname, hostlen)) {
-      failf(data, "SSL: certificate subject name '%s' does not match "
-            "target hostname '%s'", cn, peer->origin->user_hostname);
+      failf(data, "SSL: certificate subject name '%.*s' does not match "
+            "target hostname '%s'", cnlen, cn, peer->origin->user_hostname);
       result = CURLE_PEER_FAILED_VERIFICATION;
     }
     else {
-      infof(data, " common name: %s (matched)", cn);
+      infof(data, " common name: %.*s (matched)", cnlen, cn);
     }
     if(free_cn)
       OPENSSL_free(cn);
```
