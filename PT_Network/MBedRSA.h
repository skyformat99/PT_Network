#pragma once
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
class MBedRSA
{
public:
	MBedRSA();
	~MBedRSA();
public:
	int setPublicKeyFile(const char* path);
	int setPrivateKeyFile(const char* path, const char* password);

	bool publicKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength);
	bool privateKeyDecrypt(unsigned char* cipherText, int cipherTextLength, unsigned char*& plainText, int& plainTextLength);
	bool privateKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength);
	bool publicKeyDecrypt(unsigned char* cipherText, int& cipherTextLength, unsigned char*& plainText, int& plainTextLength);
private:
	void init();
private:
	mbedtls_pk_context pubPk;
	mbedtls_pk_context priPk;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

};

