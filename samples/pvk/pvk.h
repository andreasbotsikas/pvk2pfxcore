/* pvk.h */
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

#ifndef HEADER_PVK_H
#define HEADER_PVK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/bio.h>
#include <openssl/x509.h>

/* Compatibility stuff */

#ifndef OPENSSL_malloc
#define OPENSSL_malloc Malloc
#define OPENSSL_free Free
#endif
 

/* PVK file information */

typedef struct {
long magic;
long res;
long keytype;
long crypt;
long saltlen;
long keylen;
int encr;
unsigned char *salt;
unsigned char btype;
unsigned char version;
unsigned short reserved;
unsigned long keyalg;
unsigned char *key;
} PVK_DAT;

#define PVK_MAGIC	0xb0b5f11e
#define PVK_SALTLEN	0x10
#define PVK_NONE        0x0
#define PVK_WEAK        0x1
#define PVK_STRONG      0x2
#define PKEYBLOB	0x7
#define PVK_SIG         0x2
#define PVK_KEYX        0x1
#define RSA_KEYX	0xa400
#define RSA_SIG		0x2400

#ifndef ERR_file_name
#define ERR_file_name __FILE__
#endif

#define PVKerr(f,r) ERR_PVK_error((f),(r),ERR_file_name, __LINE__)

void ERR_load_PVK_strings(void);
void ERR_PVK_error(int function, int reason, char *file, int line);
int pvk_decrypt (PVK_DAT *pvk, char *pass);
RSA *pvk2rsa (PVK_DAT *pvk);
int pvk_read(BIO *in, PVK_DAT *pvk);
int pvk_write(BIO *out, PVK_DAT *pvk);
int pvk_encrypt (PVK_DAT *pvk, char *pass, int encr);
int rsa2pvk (RSA *rsa, PVK_DAT *pvk, unsigned long alg);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the PVK functions. */

/* Function codes. */
#define PVK_F_LEND2BN					 100
#define PVK_F_PVK2RSA					 101
#define PVK_F_PVK_DECRYPT				 102
#define PVK_F_PVK_ENCRYPT				 103
#define PVK_F_PVK_READ					 104
#define PVK_F_PVK_WRITE					 105
#define PVK_F_RSA2PVK					 106

/* Reason codes. */
#define PVK_R_BAD_MAGIC_NUMBER				 100
#define PVK_R_DECRYPT_ERROR				 101
#define PVK_R_FILE_WRITE_ERROR				 102
#define PVK_R_HEADER_READ_ERROR				 103
#define PVK_R_INVALID_PRIVATE_KEY_FORMAT		 104

#ifdef  __cplusplus
}
#endif
#endif
