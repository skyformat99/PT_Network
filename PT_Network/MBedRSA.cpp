#include "stdafx.h"
#include "MBedRSA.h"
#include <stdlib.h>
#include <string>
const char* const pers = "qihui_@#45*!^MBedRSA_jinqiu_sdjklsdk";

MBedRSA::MBedRSA()
{

	init();
}

void MBedRSA::init()
{
	mbedtls_pk_init(&pubPk);
	mbedtls_pk_init(&priPk);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
}

MBedRSA::~MBedRSA()
{

	mbedtls_pk_free(&priPk);
	mbedtls_pk_free(&pubPk);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

}

int MBedRSA::setPublicKeyFile(const char* path)
{
	return mbedtls_pk_parse_public_keyfile(&pubPk, path);
}

int MBedRSA::setPrivateKeyFile(const char* path, const char* password)
{
	return mbedtls_pk_parse_keyfile(&priPk, path, password);
}

bool MBedRSA::publicKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength)
{
	if(!plainText || !plainTextLength)
	{
		return false;
	}

	mbedtls_rsa_context* pubRsa = mbedtls_pk_rsa(pubPk);

	if(!pubRsa)
	{
		return false;
	}

	bool isInitByself = false;

	if(!cipherText)
	{
		cipherText = (unsigned char*)malloc(pubRsa->len);
		isInitByself = true;
	}

	cipherTextLength = pubRsa->len;
	int ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(pubRsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, plainTextLength, plainText, cipherText);

	if(ret != 0)
	{
		if(isInitByself)
		{
			free(cipherText);
			cipherText = NULL;
		}

		return false;
	}

	return true;

}

bool MBedRSA::privateKeyDecrypt(unsigned char* cipherText, int cipherTextLength, unsigned char*& plainText, int& plainTextLength)
{
	if(!cipherText || !cipherTextLength)
	{
		return false;
	}

	mbedtls_rsa_context* priRsa = mbedtls_pk_rsa(priPk);

	if(!priRsa)
	{
		return false;
	}

	bool isInitByself = false;

	if(!plainText)
	{
		plainText = (unsigned char*)malloc(priRsa->len);
		isInitByself = true;
	}

	size_t len = 0;
	int ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(priRsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &len, cipherText, plainText, priRsa->len);
	plainTextLength = len;

	if(ret != 0)
	{
		if(isInitByself)
		{
			free(plainText);
			plainText = NULL;
		}

		return false;
	}

	return true;
}

bool MBedRSA::privateKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength)
{
	if(!plainText || !plainTextLength)
	{
		return false;
	}

	mbedtls_rsa_context* priRsa = mbedtls_pk_rsa(priPk);

	if(!priRsa)
	{
		return false;
	}

	bool isInitByself = false;

	if(!cipherText)
	{
		cipherText = (unsigned char*)malloc(priRsa->len);
		isInitByself = true;
	}

	cipherTextLength = priRsa->len;
	int ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(priRsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, plainTextLength, plainText, cipherText);

	if(ret != 0)
	{
		if(isInitByself)
		{
			free(cipherText);
			cipherText = NULL;
		}

		return false;
	}

	return true;
}

bool MBedRSA::publicKeyDecrypt(unsigned char* cipherText, int& cipherTextLength, unsigned char*& plainText, int& plainTextLength)
{
	if(!cipherText || !cipherTextLength)
	{
		return false;
	}

	mbedtls_rsa_context* pubRsa = mbedtls_pk_rsa(pubPk);

	if(!pubRsa)
	{
		return false;
	}

	bool isInitByself = false;

	if(!plainText)
	{
		plainText = (unsigned char*)malloc(pubRsa->len);
		isInitByself = true;
	}

	size_t len = 0;
	int ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(pubRsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, &len, cipherText, plainText, pubRsa->len);
	plainTextLength = len;

	if(ret != 0)
	{
		if(isInitByself)
		{
			free(plainText);
			plainText = NULL;
		}

		return false;
	}

	return true;
}