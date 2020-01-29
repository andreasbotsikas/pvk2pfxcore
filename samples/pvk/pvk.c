/* pvk.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2001.
 */
/* ====================================================================
 * Copyright (c) 2000,2001 The OpenSSL Project.  All rights reserved.
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
#include <openssl/pem.h>
#include <openssl/err.h>
#include "pvk.h"

BIO *bio_err = NULL;

int main(int argc, char **argv)
{
	char **args, *infile = NULL, *outfile = NULL;
	BIO *in = NULL, *out = NULL;
	int topvk = 0, nocrypt = 0;
        unsigned long alg = -1, encr = PVK_WEAK;
	RSA *rsa;
	PVK_DAT pvk;
	char pass[50];
	int badarg = 0;
	const EVP_CIPHER *cipher;
	cipher = EVP_des_ede3_cbc();
	if (bio_err == NULL) bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	ERR_load_crypto_strings();
	ERR_load_PVK_strings();
        OpenSSL_add_all_algorithms();
	args = argv + 1;
	while (!badarg && *args && *args[0] == '-') {
		if (!strcmp (*args, "-topvk")) topvk = 1;
                else if (!strcmp (*args, "-strong")) encr = PVK_STRONG;
                else if (!strcmp (*args, "-sig")) alg = RSA_SIG;
                else if (!strcmp (*args, "-exc")) alg = RSA_KEYX;
		else if (!strcmp (*args, "-nocrypt")) {
			nocrypt = 1;
			cipher = NULL;
		} else if (!strcmp (*args, "-in")) {
			if (args[1]) {
				args++;
				infile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-out")) {
			if (args[1]) {
				args++;
				outfile = *args;
			} else badarg = 1;
		} else badarg = 1;
		args++;
	}

	if (badarg) {
                BIO_printf (bio_err, "PVK file conversion tool 0.12\n");
		BIO_printf (bio_err, "Usage pvk [options]\n");
		BIO_printf (bio_err, "where options are\n");
                BIO_printf (bio_err, "-in file  input file\n");
                BIO_printf (bio_err, "-out file output file\n");
                BIO_printf (bio_err, "-topvk    output PVK file\n");
                BIO_printf (bio_err, "-nocrypt  don't encrypt output file\n");
                BIO_printf (bio_err, "-strong   use strong encryption for PVK file\n");
                BIO_printf (bio_err, "-sig      store key as a signature key\n");
		return (1);
	}

	if (infile) {
		if (!(in = BIO_new_file (infile, topvk ? "r":"rb"))) {
			BIO_printf (bio_err,
				 "Can't open input file %s\n", infile);
			return (1);
		}
	} else in = BIO_new_fp (stdin, BIO_NOCLOSE);

	if (outfile) {
		if (!(out = BIO_new_file (outfile, topvk ? "wb":"w"))) {
			BIO_printf (bio_err,
				 "Can't open output file %s\n", outfile);
			return (1);
		}
	} else out = BIO_new_fp (stdout, BIO_NOCLOSE);

	if (topvk) {
		if (!(rsa = PEM_read_bio_RSAPrivateKey (in, NULL, NULL, NULL))) {
			BIO_printf (bio_err, "Error reading key\n", outfile);
			ERR_print_errors(bio_err);
			return (1);
		}
                if (!rsa2pvk(rsa, &pvk, alg)) {
			BIO_printf (bio_err, "Error converting key\n", outfile);
			ERR_print_errors(bio_err);
			return (1);
		}
		if(!nocrypt) {
			EVP_read_pw_string (pass, 50, "Enter Password:", 1);
                        pvk_encrypt(&pvk, pass, encr);
		}
		pvk_write(out, &pvk);
		BIO_free(out);
		return (0);
	}

	if (!pvk_read(in, &pvk)) {
		BIO_printf (bio_err, "Error reading key\n", outfile);
		ERR_print_errors(bio_err);
		return (1);
	}

	if (!pvk_decrypt(&pvk, NULL)) {
		EVP_read_pw_string (pass, 50, "Enter Password:", 0);
		if(!pvk_decrypt(&pvk, pass)) {
			BIO_printf(bio_err, "Error Decrypting File: Invalid password?\n");
			ERR_print_errors(bio_err);
			return 1;
		}
	}

	rsa = pvk2rsa(&pvk);

	PEM_write_bio_RSAPrivateKey (out, rsa, cipher, NULL, 0, NULL, NULL);
	BIO_free(out);

	return (0);
}
