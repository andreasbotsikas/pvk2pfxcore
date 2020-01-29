/* pvkwrite.c */
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
#include <openssl/rand.h>
#include <openssl/err.h>
#include "pvk.h"

static int write_word(BIO *out, unsigned short dat)
{
	unsigned char buf[2];
	buf[0] = dat & 0xff;
	buf[1] = (dat >> 8) & 0xff;
	if (BIO_write(out, buf, 2) != 2) return 0;
	return 1;
}

static int write_dword(BIO *out, unsigned long dat)
{
	unsigned char buf[4];
	buf[0] = dat & 0xff;
	buf[1] = (dat >> 8) & 0xff;
	buf[2] = (dat >> 16) & 0xff;
	buf[3] = (dat >> 24) & 0xff;
	if (BIO_write(out, buf, 4) != 4) return 0;
	return 1;
}

static void put_dword(unsigned char **p, unsigned long dat)
{
	unsigned char *buf;
	buf = *p;
	buf[0] = dat & 0xff;
	buf[1] = (dat >> 8) & 0xff;
	buf[2] = (dat >> 16) & 0xff;
	buf[3] = (dat >> 24) & 0xff;
	*p += 4;
}

int pvk_write(BIO *out, PVK_DAT *pvk)
{
	int keylen;
	if( !write_dword(out, pvk->magic) ||
            !write_dword(out, pvk->res) ||
            !write_dword(out, pvk->keytype) ||
            !write_dword(out, pvk->crypt) ||
	    !write_dword(out, pvk->saltlen) ||
	    !write_dword(out, pvk->keylen) ) goto err;
	if (pvk->saltlen) 
		if(BIO_write(out, pvk->salt, pvk->saltlen) != pvk->saltlen)
								   goto err;
	if(BIO_write(out, &pvk->btype, 1) != 1) goto err;
	if(BIO_write(out, &pvk->version, 1) != 1) goto err;
	if(!write_word(out, pvk->reserved)) goto err;
	if(!write_dword(out, pvk->keyalg)) goto err;

	if (pvk->keylen > 8) {
		keylen = pvk->keylen - 8;
		if(BIO_write(out, pvk->key, keylen) != keylen) goto err;
	}
	return 1;

	err:
	PVKerr(PVK_F_PVK_WRITE,PVK_R_FILE_WRITE_ERROR);
	return 0;
}

int pvk_encrypt(PVK_DAT *pvk, char *pass, int encr)
{
	EVP_MD_CTX ctx;
	EVP_CIPHER_CTX cctx;
	unsigned char *buf;
	unsigned char tmpkey[EVP_MAX_KEY_LENGTH];
	int outlen;
	pvk->saltlen = PVK_SALTLEN;
	RAND_seed(pass, strlen(pass));
	if(!(pvk->salt = OPENSSL_malloc(pvk->saltlen))) {
		PVKerr(PVK_F_PVK_ENCRYPT,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	RAND_bytes(pvk->salt, pvk->saltlen);
	if(!(buf = OPENSSL_malloc(pvk->keylen + 8))) {
		PVKerr(PVK_F_PVK_ENCRYPT,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	EVP_DigestInit(&ctx, EVP_sha1());
	EVP_DigestUpdate(&ctx, pvk->salt, pvk->saltlen);
	EVP_DigestUpdate(&ctx, pass, strlen(pass));
	EVP_DigestFinal(&ctx, tmpkey, NULL);

        if(encr == PVK_WEAK) memset(tmpkey + 5, 0, 11);

	EVP_EncryptInit(&cctx, EVP_rc4(), tmpkey, NULL);
	EVP_EncryptUpdate(&cctx, buf, &outlen, pvk->key, pvk->keylen);
	/* Not needed but do it to cleanup */
	EVP_EncryptFinal(&cctx, buf + outlen, &outlen);
	OPENSSL_free(pvk->key);
	pvk->key = buf;
        pvk->crypt = 1;
        pvk->encr = encr;
        memset(tmpkey, 0, EVP_MAX_KEY_LENGTH);
	return 1;
}

/* Convert bignum to little endian format */ 
static int BN2lend (BIGNUM *num, unsigned char *p)
{
	int nbyte, i;
	unsigned char c;
	nbyte = BN_num_bytes(num);
	BN_bn2bin (num, p);
	/* Inplace byte reversal */
	for (i = 0; i < nbyte / 2; i++) {
		c = p[i];
		p[i] = p[nbyte - i - 1];
		p[nbyte - i - 1] = c;
	}
	return 1;
}

/* Convert RSA key into PVK structure */

int rsa2pvk(RSA *rsa, PVK_DAT *pvk, unsigned long alg)
{
	int numbytes;
	unsigned char *p;

	/* Initialise structure */
	pvk->magic = PVK_MAGIC;

        pvk->res = 0;
        pvk->crypt = 0;
	pvk->btype = PKEYBLOB;
	pvk->version = 2;
	pvk->reserved = 0;
	pvk->saltlen = 0;
	pvk->salt = NULL;
        pvk->encr = PVK_NONE;

        if(alg == -1) pvk->keyalg = RSA_SIG;
        else pvk->keyalg = alg;

        if(pvk->keyalg == RSA_KEYX) pvk->keytype = PVK_KEYX;
        else if(pvk->keyalg == RSA_SIG) pvk->keytype = PVK_SIG;

	/* Set up a private key blob */
	numbytes = BN_num_bytes (rsa->n);
	/* Allocate enough room for blob */
	if (!(pvk->key = calloc(1, 12 + numbytes * 5))) {
		PVKerr(PVK_F_RSA2PVK,ERR_R_MALLOC_FAILURE);
		return 0;
	}

	p = pvk->key;

	memcpy(p, "RSA2", 4);
	
	p+= 4;

	put_dword(&p, numbytes << 3);	/* Number of bits */
	put_dword(&p, BN_get_word(rsa->e)); /* Public exponent */

	/* Convert each element */

	BN2lend (rsa->n, p);
	p += numbytes;
	BN2lend (rsa->p, p);
	p += numbytes/2;
	BN2lend (rsa->q, p);
	p += numbytes/2;
	BN2lend (rsa->dmp1, p);
	p += numbytes/2;
	BN2lend (rsa->dmq1, p);
	p += numbytes/2;
	BN2lend (rsa->iqmp,p);
	p += numbytes/2;
	BN2lend (rsa->d, p);
	p += numbytes;
	pvk->keylen = p - pvk->key + 8;
	RAND_seed(pvk->key, pvk->keylen);
	return 1;
}
