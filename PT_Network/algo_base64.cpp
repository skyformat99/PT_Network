#include "algo_base64.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
AlgoBase64::AlgoBase64()
{
}

AlgoBase64::~AlgoBase64()
{
}

void  AlgoBase64::Base64Encode(unsigned char*plainText, int plainTextLen, unsigned char*& cipherText, int& cipherLen, bool with_new_line)
{
	BIO* bmem = BIO_new(BIO_s_mem());
	BIO* b64 = BIO_new(BIO_f_base64());
	BUF_MEM* bptr = NULL;

	if (!with_new_line)
	{
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}

	b64 = BIO_push(b64, bmem);
	BIO_write(b64, plainText, plainTextLen);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	if (!cipherText)
	{
		cipherText = new unsigned char[bptr->length + 1];
		memset(cipherText, 0, bptr->length + 1);
	}

	memcpy_s(cipherText, bptr->length, bptr->data, bptr->length);
	cipherLen = bptr->length;
	BIO_free_all(b64);
}

void  AlgoBase64::Base64Decode(unsigned char*cipherText, int cipherTextLen, unsigned char*& plainText, int& plainTextLen, bool with_new_line)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;

	if (!plainText)
	{
		plainText = (unsigned char *)malloc(cipherTextLen);
		memset(plainText, 0, cipherTextLen);
	}

	b64 = BIO_new(BIO_f_base64());

	if (!with_new_line)
	{
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}

	bmem = BIO_new_mem_buf(cipherText, cipherTextLen);
	bmem = BIO_push(b64, bmem);
	plainTextLen = BIO_read(bmem, plainText, cipherTextLen);
	BIO_free_all(bmem);
}