/* pvkread.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "pvk.h"

static int read_word(BIO *in, unsigned short *dat);
static int read_dword(BIO *in, unsigned long *dat);
static unsigned long get_dword(unsigned char **p);
static BIGNUM *lend2BN(unsigned char **nptr, int len);
static int scan_magic(BIO *in, unsigned long *magic);

static int read_word(BIO *in, unsigned short *dat)
{
	unsigned char buf[2];
	if (BIO_read(in, buf, 2) != 2) return 0;
	*dat = buf[0] + (buf[1] << 8);
	return 1;
}

static int read_dword(BIO *in, unsigned long *dat)
{
	unsigned char buf[4];
	if (BIO_read(in, buf, 4) != 4) return 0;
	*dat = buf[0] + (buf[1] << 8) + (buf[2] << 16) + (buf[3] << 24);
	return 1;
}

static unsigned long get_dword(unsigned char **p)
{
	unsigned long ret;
	unsigned char *buf;
	buf = *p;
	ret = buf[0] + (buf[1] << 8) + (buf[2] << 16) + (buf[3] << 24);
	*p += 4;
	return ret;
}

static int scan_magic(BIO *in, unsigned long *magic)
{
	int i;
	char dummy[4];
	for(i = 0; i < 4; i++) {
		if(i && (BIO_read(in, dummy, i) != i)) return 0;
		while(read_dword(in, magic)) if(*magic == PVK_MAGIC) return 1;
		BIO_reset(in);
	}
	return 1;
}

int pvk_read(BIO *in, PVK_DAT *pvk)
{
	if(	!scan_magic(in, &pvk->magic) ||
        	!read_dword(in, &pvk->res) ||
        	!read_dword(in, &pvk->keytype) ||
        	!read_dword(in, &pvk->crypt) ||
		!read_dword(in, &pvk->saltlen) ||
		!read_dword(in, &pvk->keylen) ) {
		PVKerr(PVK_F_PVK_READ,PVK_R_HEADER_READ_ERROR);
		return 0;
	}
	if(pvk->magic != PVK_MAGIC) {
		PVKerr(PVK_F_PVK_READ,PVK_R_BAD_MAGIC_NUMBER);
		return 0;
	}
	if (pvk->saltlen) {
		if(!(pvk->salt = OPENSSL_malloc(pvk->saltlen))) {
			PVKerr(PVK_F_PVK_READ,ERR_R_MALLOC_FAILURE);
			return 0;
		}
		if(BIO_read(in, pvk->salt, pvk->saltlen) != pvk->saltlen) {
			PVKerr(PVK_F_PVK_READ,PVK_R_HEADER_READ_ERROR);
			return 0;
		}
	} else pvk->salt = NULL;

	if( (BIO_read(in, &pvk->btype, 1) != 1) ||
	    (BIO_read(in, &pvk->version, 1) != 1) ||
	    !read_word(in, &pvk->reserved) ||
	    !read_dword(in, &pvk->keyalg) ) {
		PVKerr(PVK_F_PVK_READ,PVK_R_HEADER_READ_ERROR);
		return 0;
	}

	if (pvk->keylen) {
		pvk->keylen -= 8;
		if(!(pvk->key = OPENSSL_malloc(pvk->keylen))) {
			PVKerr(PVK_F_PVK_READ,ERR_R_MALLOC_FAILURE);
			return 0;
		}
		if(BIO_read(in, pvk->key, pvk->keylen) != pvk->keylen) {
			PVKerr(PVK_F_PVK_READ,PVK_R_HEADER_READ_ERROR);
			return 0;
		}
	} else pvk->key = NULL;
	return 1;
}

int pvk_decrypt(PVK_DAT *pvk, char *pass)
{
	EVP_MD_CTX ctx;
	EVP_CIPHER_CTX cctx;
	unsigned char *buf;
	unsigned char tmpkey[EVP_MAX_KEY_LENGTH];
	int outlen;
        if (!pvk->crypt && !pvk->saltlen) {
                pvk->encr = PVK_NONE;
                return 1;
        }
	if (!pass) return 0; /* Not an error: just test if encrypted file */
	if(!(buf = OPENSSL_malloc(pvk->keylen + 8))) {
		PVKerr(PVK_F_PVK_DECRYPT,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	EVP_DigestInit(&ctx, EVP_sha1());
	EVP_DigestUpdate(&ctx, pvk->salt, pvk->saltlen);
	EVP_DigestUpdate(&ctx, pass, strlen(pass));
	EVP_DigestFinal(&ctx, tmpkey, NULL);
        EVP_DecryptInit(&cctx, EVP_rc4(), tmpkey, NULL);
	EVP_DecryptUpdate(&cctx, buf, &outlen, pvk->key, pvk->keylen);
	if(strncmp(buf, "RSA2", 4)) {
                /* Didn't work: try weak encryption */
                memset(tmpkey+5, 0, 11);
                EVP_DecryptFinal(&cctx, buf + outlen, &outlen);
                EVP_DecryptInit(&cctx, EVP_rc4(), tmpkey, NULL);
                EVP_DecryptUpdate(&cctx, buf, &outlen, pvk->key, pvk->keylen);
                if(strncmp(buf, "RSA2", 4)) {
			PVKerr(PVK_F_PVK_DECRYPT,PVK_R_DECRYPT_ERROR);
                        OPENSSL_free(buf);
                        return 0;
                } else pvk->encr = PVK_WEAK;
        } else pvk->encr = PVK_STRONG;
	/* Not needed but do it to cleanup */
	EVP_DecryptFinal(&cctx, buf + outlen, &outlen);
	OPENSSL_free(pvk->key);
	pvk->key = buf;
        memset(tmpkey, 0, EVP_MAX_KEY_LENGTH);
	return 1;
}


RSA *pvk2rsa (PVK_DAT *pvk)
{
	RSA *rsa;
	unsigned char *keytmp;
	int pubexp, keylen, pvklen;
	rsa = RSA_new();
	if (!rsa) return NULL;
	keytmp = pvk->key + 4;

	pvklen = pvk->keylen - 12;

	if (pvklen < 0) return NULL;

	keylen = get_dword(&keytmp) >> 3;
	pubexp = get_dword(&keytmp);

 	if (pvklen < ((keylen/2)* 9)) goto err;

	if(!(rsa->e = BN_new ())) goto err;
	BN_set_word (rsa->e, pubexp);
	if(!(rsa->n = lend2BN (&keytmp, keylen))) goto err;
	if(!(rsa->p = lend2BN (&keytmp, keylen/2))) goto err;
	if(!(rsa->q = lend2BN (&keytmp, keylen/2))) goto err;
	if(!(rsa->dmp1 = lend2BN (&keytmp, keylen/2))) goto err;
	if(!(rsa->dmq1 = lend2BN (&keytmp, keylen/2))) goto err;
	if(!(rsa->iqmp = lend2BN (&keytmp, keylen/2))) goto err;
	if(!(rsa->d = lend2BN (&keytmp, keylen))) goto err;
	return rsa;
	err:
	PVKerr(PVK_F_PVK2RSA,PVK_R_INVALID_PRIVATE_KEY_FORMAT);
	RSA_free(rsa);
	return NULL;
}

/* Convert little endian number to BIGNUM */
static BIGNUM *lend2BN (unsigned char **nptr, int len)
{
	unsigned char *ntmp, *p, *num;
	int i;
	BIGNUM *bn;
	num = *nptr;
	if(!(ntmp = OPENSSL_malloc (len))) {
		PVKerr(PVK_F_LEND2BN,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	/* Reverse byte order */
	for (i = 0, p = ntmp + len - 1; i < len; i++, num++, p--) *p = *num; 
	bn = BN_bin2bn (ntmp, len, NULL);
	OPENSSL_free (ntmp);
	if (!bn) return NULL;
	/* Increment pointer */
	*nptr+=len;
	return bn;
}
