#include "RsaEncryptor.h"
#include <assert.h>
#include <mutex>
#include <thread>
#include <vector>
#include <memory>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

auto BIODeleter = [](BIO *bio)
{
	if(nullptr != bio) BIO_free(bio);
};
auto RSADeleter = [](RSA *rsa)
{
	if(nullptr != rsa) RSA_free(rsa);
};

bool RsaEncryptor::Init()
{
	std::call_once(m_init_once_flag, []
	{
		ERR_load_ERR_strings();
		ERR_load_crypto_strings();
	});
	return true;
}

bool RsaEncryptor::SetPublicKeyFromFile(const std::string &publicKeyFile)
{
	bool result = true;
	std::shared_ptr<BIO> bio;

	do
	{

		bio.reset(BIO_new_file(publicKeyFile.c_str(), "r"), BIODeleter);

		if(bio.get() == nullptr)
		{
			result = false;
			break;
		}

		m_rsaPublic.reset(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
						  RSADeleter);

		if(nullptr == m_rsaPublic.get())
		{
			result = false;
			break;
		}
	}
	while(false);


	return result;
}

bool RsaEncryptor::SetPrivateKeyFromFile(const std::string &privateKeyFile,
		std::string password)
{
	bool result = true;
	std::shared_ptr<BIO> bio;

	do
	{
		if(true == m_isUseDecrypt)
		{
			result = false;
			break;
		}

		// 如果密钥文件使用了密钥
		if(!password.empty())
			OpenSSL_add_all_algorithms(); // 一定要调用EVP_cleanup(), 不然内存泄漏;

		bio.reset(BIO_new_file(privateKeyFile.c_str(), "rb"), BIODeleter);

		if(bio.get() == nullptr)
		{
			result = false;
			break;
		}

		if(password.empty())
			m_rsaPrivate.reset(PEM_read_bio_RSAPrivateKey(bio.get(),
							   nullptr, nullptr, nullptr), RSADeleter);
		else
			m_rsaPrivate.reset(PEM_read_bio_RSAPrivateKey(bio.get(),
							   nullptr, nullptr, const_cast<char *>(password.c_str())),
							   RSADeleter);

		if(nullptr == m_rsaPrivate)
		{
			result = false;
			break;
		}
	}
	while(false);

	return result;
}

void RsaEncryptor::Destory()
{
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}

RsaEncryptor::~RsaEncryptor()
{
	Destory();
}



std::string RsaEncryptor::GetEncrytOrDecryptInfo() const
{
	// 文档说至少120长度
	char errorInfo[120];
	memset(errorInfo, 0, 120);

	ERR_error_string(m_rsaErrorNo, errorInfo);
	return errorInfo;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
bool RsaEncryptor::publicKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength)
{
	if(!m_rsaPublic)
	{
		return false;
	}

	int flen = RSA_size(m_rsaPublic.get());
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
		cipherText = (unsigned char*)malloc(RSA_size(m_rsaPublic.get()));
	}

	//使用公钥加密
	cipherTextLength = RSA_public_encrypt(flen, plainText, cipherText, m_rsaPublic.get(), padding);

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

bool RsaEncryptor::privateKeyDecrypt(unsigned char* cipherText, int cipherTextLength, unsigned char*& plainText, int& plainTextLength)
{
	if(!m_rsaPrivate)
	{
		return false;
	}

	int flen = RSA_size(m_rsaPrivate.get());
	int padding = RSA_PKCS1_OAEP_PADDING;
	flen = flen - 2 * SHA_DIGEST_LENGTH - 2;
	bool plainInitBySelf = false;

	if(!plainText)
	{
		plainInitBySelf = true;
		plainText = (unsigned char*)malloc(RSA_size(m_rsaPrivate.get()));
	}

	//使用私钥解密

	plainTextLength = RSA_private_decrypt(cipherTextLength, cipherText, plainText, m_rsaPrivate.get(), padding);

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

bool RsaEncryptor::privateKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength)
{
	if(!m_rsaPrivate)
	{
		return false;
	}

	int flen = RSA_size(m_rsaPrivate.get());
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
		cipherText = (unsigned char*)malloc(RSA_size(m_rsaPrivate.get()));
	}

	//使用私钥加密
	cipherTextLength = RSA_private_encrypt(plainTextLength, plainText, cipherText, m_rsaPrivate.get(), padding);

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

bool  RsaEncryptor::publicKeyDecrypt(unsigned char* cipherText, int& cipherTextLength, unsigned char*& plainText, int& plainTextLength)
{
	if(!m_rsaPublic)
	{
		return false;
	}

	int flen = RSA_size(m_rsaPublic.get());
	int padding = RSA_PKCS1_PADDING;
	flen -= 2;
	bool plainInitBySelf = false;

	if(!plainText)
	{
		plainInitBySelf = true;
		plainText = (unsigned char*)malloc(RSA_size(m_rsaPublic.get()));
	}

	//使用私钥加密
	plainTextLength = RSA_public_decrypt(cipherTextLength, cipherText, plainText, m_rsaPublic.get(), padding);

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

void RsaEncryptor::handleErrors()
{
	//  ERR_load_crypto_strings();
	//  ERR_load_BIO_strings();
	int sslerror = ERR_get_error();
	char buf[2048] = { 0 };
	char* szError = ERR_error_string(sslerror, buf);
	puts(buf);
	ERR_free_strings();
}