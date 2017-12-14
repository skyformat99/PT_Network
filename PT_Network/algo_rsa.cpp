#include "algo_rsa.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

AlogRSA::AlogRSA()
{
	rsa_ctx_ = RSA_new();
}

AlogRSA::~AlogRSA()
{
	RSA_free(rsa_ctx_);
}

bool AlogRSA::loadPublicKey(const char* path_public_key)
{
	if(!rsa_ctx_)
	{
		return false;
	}

	if(NULL == path_public_key)
	{
		return false;
	}

	BIO* file = BIO_new_file(path_public_key, "rb");

	if(NULL == file)
	{
		std::cout << "read file error!\n";
		return false;
	}

	PEM_read_bio_RSA_PUBKEY(file, &rsa_ctx_, NULL, NULL);
	BIO_free(file);

	if(rsa_ctx_->e != NULL)
	{
		return true;
	}

//  ERR_load_crypto_strings();
//  ERR_load_BIO_strings();
	int sslerror = ERR_get_error();
	char buf[2048] = { 0 };
	char* szError = ERR_error_string(sslerror, buf);
	puts(buf);
	//EVP_cleanup();
	return false;
}

bool AlogRSA::loadPrivateKey(const char* path_private_key, const char* pem_password)
{
	if(!rsa_ctx_)
	{
		return false;
	}

	if(NULL == path_private_key)
	{
		return false;
	}

	BIO* file = BIO_new_file(path_private_key, "rb");

	if(NULL == file)
	{
		std::cout << "read file error!\n";
		return false;
	}

	//OpenSSL_add_all_algorithms();
	PEM_read_bio_RSAPrivateKey(file, &rsa_ctx_, NULL, (char*)pem_password);
	BIO_free(file);
	//EVP_cleanup();

	if(rsa_ctx_->d != NULL)
	{
		return true;
	}

//  ERR_load_crypto_strings();
//  ERR_load_BIO_strings();
	int sslerror = ERR_get_error();
	char buf[2048] = { 0 };
	char* szError = ERR_error_string(sslerror, buf);
	puts(buf);
	ERR_free_strings();
	return false;
}

int AlogRSA::pem_password_cb(char *buf, int size, int rwflag, void *userdata)
{
	if(!userdata)
	{
		return 0;
	}

	char* key = (char*)userdata;
	memcpy_s(buf, strlen(key), key, strlen(key));
	return strlen(buf);
}

bool AlogRSA::publicKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength)
{
	if(!rsa_ctx_)
	{
		return false;
	}

	int flen = RSA_size(rsa_ctx_);
	int padding = RSA_PKCS1_OAEP_PADDING;
	flen = flen - 2 * SHA_DIGEST_LENGTH - 2;

	if(plainTextLength > flen)
	{
		return false;
	}

	bool cipherInitBySelf = false;

	if(!cipherText)
	{
		cipherInitBySelf = true;
		cipherText = (unsigned char*)malloc(RSA_size(rsa_ctx_));
	}

	//使用公钥加密
	cipherTextLength = RSA_public_encrypt(flen, plainText, cipherText, rsa_ctx_, padding);

	if(cipherTextLength <= 0)
	{
		handleErrors();

		if(cipherInitBySelf)
		{
			free(cipherText);
			cipherText = NULL;
			cipherTextLength = 0;
		}

		return false;
	}

	return true;
}

bool AlogRSA::privateKeyDecrypt(unsigned char* cipherText, int cipherTextLength, unsigned char*& plainText, int& plainTextLength)
{
	if(!rsa_ctx_)
	{
		return false;
	}

	int flen = RSA_size(rsa_ctx_);
	int padding = RSA_PKCS1_OAEP_PADDING;
	flen = flen - 2 * SHA_DIGEST_LENGTH - 2;
	bool plainInitBySelf = false;

	if(!plainText)
	{
		plainInitBySelf = true;
		plainText = (unsigned char*)malloc(RSA_size(rsa_ctx_));
	}

	//使用私钥解密

	plainTextLength = RSA_private_decrypt(cipherTextLength, cipherText, plainText, rsa_ctx_, padding);

	if(plainTextLength <= 0)
	{
		handleErrors();

		if(plainInitBySelf)
		{
			free(plainText);
			plainText = NULL;
			plainTextLength = 0;
		}

		return false;
	}

	return true;
}

bool AlogRSA::privateKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength)
{
	if(!rsa_ctx_)
	{
		return false;
	}

	int flen = RSA_size(rsa_ctx_);
	int padding = RSA_PKCS1_PADDING;
	flen -= 11;

	if(plainTextLength > flen)
	{
		return false;
	}

	bool cipherInitBySelf = false;

	if(!cipherText)
	{
		cipherInitBySelf = true;
		cipherText = (unsigned char*)malloc(RSA_size(rsa_ctx_));
	}

	//使用私钥加密
	cipherTextLength = RSA_private_encrypt(plainTextLength, plainText, cipherText, rsa_ctx_, padding);

	if(cipherTextLength <= 0)
	{
		handleErrors();

		if(cipherInitBySelf)
		{
			free(cipherText);
			cipherTextLength = 0;
		}

		return false;
	}

	return true;
}

bool  AlogRSA::publicKeyDecrypt(unsigned char* cipherText, int& cipherTextLength, unsigned char*& plainText, int& plainTextLength)
{
	if(!rsa_ctx_)
	{
		return false;
	}

	int flen = RSA_size(rsa_ctx_);
	int padding = RSA_PKCS1_PADDING;
	flen -= 2;
	bool plainInitBySelf = false;

	if(!plainText)
	{
		plainInitBySelf = true;
		plainText = (unsigned char*)malloc(RSA_size(rsa_ctx_));
	}

	//使用私钥加密
	plainTextLength = RSA_public_decrypt(cipherTextLength, cipherText, plainText, rsa_ctx_, padding);

	if(plainTextLength <= 0)
	{
		handleErrors();

		if(plainInitBySelf)
		{
			free(plainText);
			plainText = NULL;
			plainTextLength = 0;
		}

		return false;
	}

	return true;
}

void AlogRSA::handleErrors()
{
//  ERR_load_crypto_strings();
//  ERR_load_BIO_strings();
	int sslerror = ERR_get_error();
	char buf[2048] = { 0 };
	char* szError = ERR_error_string(sslerror, buf);
	puts(buf);
	ERR_free_strings();
}