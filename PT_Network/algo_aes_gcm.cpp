#include "algo_aes_gcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "algo_random.h"
AlgoAesGcm::AlgoAesGcm()
{
}

AlgoAesGcm::~AlgoAesGcm()
{
}

bool AlgoAesGcm::genAesRandomKey(unsigned char*& key)
{
	AlgoRandom::RAND_poll_secure_240bits();

	if(!key)
	{
		key = new unsigned char[16];
	}

	AlgoRandom::RAND_bytes_secure(key, 16);
	return true;
}

bool AlgoAesGcm::encrypt(unsigned char* plainText, int plainTextLen,
						 unsigned char* key,
						 unsigned char*& aad, int& aadLen,
						 unsigned char*& iv, int& ivLen,
						 unsigned char*& cipherText, int& cipherTextLen,
						 unsigned char*& tag)
{
	if(!plainText || 0 == plainTextLen)
	{
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if(!ctx)
	{
		return false;
	}

	bool ivInitBySelf = false;
	bool aadInitBySelf = false;
	bool cipherInitBySelf = false;
	bool tagInitBySelf = false;
	AlgoRandom::RAND_poll_secure_240bits();

	if(!iv)
	{
		iv = (unsigned char*)malloc(12);
		//iv = new unsigned char[12];
		ivLen = 12;

		//RAND_pseudo_bytes(iv, 12);
		ivInitBySelf = true;
	}

	AlgoRandom::RAND_bytes_secure(iv, ivLen);

	if(!aad)
	{
		//aad = new unsigned char[16];
		aad = (unsigned char*)malloc(16);
		aadLen = 16;
		//RAND_pseudo_bytes(aad, 16);
		aadInitBySelf = true;
	}

	AlgoRandom::RAND_bytes_secure(aad, aadLen);
	cipherTextLen = 0;

	do
	{
		//创建并初始化加密上下文
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		{
			break;
		}

		//设置IV的长度
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
		{
			break;
		}

		//初始化Key和IV
		if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		{
			break;
		}

		int len = 0;

		//提供任意的AAD Data
		if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aadLen))
		{
			break;
		}

		if(!cipherText)
		{
			//cipherText = new unsigned char[plainTextLen];
			cipherText = (unsigned char*)malloc(plainTextLen);
			cipherInitBySelf = true;
		}

		//加密明文
		if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
		{
			break;
		}

		cipherTextLen += len;

		//结束加密
		if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len))
		{
			break;
		}

		cipherTextLen += len;

		if(NULL == tag)
		{
			//tag = new unsigned char[16];
			tag = (unsigned char*)malloc(16);
			tagInitBySelf = true;
		}

		//获取Tag
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag))
		{
			break;
		}

		EVP_CIPHER_CTX_free(ctx);
		return true;
	}
	while(0);

	handleErrors();

	if(ivInitBySelf)
	{
		free(iv);
		iv = NULL;
		ivLen = 0;
	}

	if(aadInitBySelf)
	{
		free(aad);
		aad = NULL;
		aadLen = 0;
	}

	if(cipherInitBySelf)
	{
		free(cipherText);
		cipherText = NULL;
		cipherTextLen = 0;
	}

	if(tagInitBySelf)
	{
		free(tag);
		tag = NULL;
	}

	EVP_CIPHER_CTX_free(ctx);
	return false;
}

bool AlgoAesGcm::decrypt(unsigned char *cipherText, int cipherTextLen,
						 unsigned char *key,
						 unsigned char *aad, int aadLen,
						 unsigned char *tag,
						 unsigned char *iv, int ivLen,
						 unsigned char*& plainText, int& plainTextLen)
{
	if(!cipherText || 0 == cipherTextLen)
	{
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if(!ctx)
	{
		return false;
	}

	bool plainInitBySelf = false;

	do
	{
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		{
			break;
		}

		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
		{
			break;
		}

		if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		{
			break;
		}

		int len = 0;

		if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aadLen))
		{
			break;
		}

		if(!plainText)
		{
			plainText = (unsigned char*)malloc(cipherTextLen);
			plainInitBySelf = true;
		}

		if(!EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
		{
			break;
		}

		plainTextLen = len;

		//设置Tag
		if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		{
			break;
		}

		int ret = EVP_DecryptFinal_ex(ctx, plainText + plainTextLen, &len);

		if(ret > 0)
		{
			plainTextLen += len;
			EVP_CIPHER_CTX_free(ctx);
			return true;
		}
	}
	while(0);

	handleErrors();
	EVP_CIPHER_CTX_free(ctx);

	if(plainInitBySelf)
	{
		free(plainText);
		plainText = NULL;
		plainTextLen = 0;
	}

	return false;
}

void AlgoAesGcm::handleErrors()
{
//  ERR_load_crypto_strings();
//  ERR_load_BIO_strings();
	int sslerror = ERR_get_error();
	char buf[2048] = { 0 };
	char* szError = ERR_error_string(sslerror, buf);
	puts(buf);
	//EVP_cleanup();
}