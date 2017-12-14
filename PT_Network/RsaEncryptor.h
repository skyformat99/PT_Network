#ifndef MID_RSA_RSAENCRYPTOR_H__
#define MID_RSA_RSAENCRYPTOR_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string>
#include <iostream>
#include <memory>

#include <openssl/rsa.h>

class RsaEncryptor
{
public:
	RsaEncryptor() :
		m_isInit(false),
		m_isUseEncrypt(false),
		m_isUseDecrypt(false),
		m_rsaPublic(nullptr),
		m_rsaPrivate(nullptr),
		m_rsaErrorNo(0) {}
	RsaEncryptor(const RsaEncryptor &) = delete;
	RsaEncryptor &operator=(const RsaEncryptor &) = delete;

	bool SetPublicKeyFromFile(const std::string &publicKeyFile);

	bool SetPrivateKeyFromFile(const std::string &privateKeyFile, std::string password = "");

	/// <summary>
	/// RSA算法使用公钥加密 填充方式为RSA_PKCS1_OAEP_PADDING
	/// </summary>
	/// <param name="plainText">明文 长度需小于等于RSA_SIZE-2 * SHA_DIGEST_LENGTH(20) - 2字节</param>
	/// <param name="plainTextLength">明文长度</param>
	/// <param name="cipherText">密文 传输NULL且返回true时，使用完需要释放,delete[] cipherText</param>
	/// <param name="cipherTextLength">密文长度</param>
	/// <returns></returns>
	bool publicKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength);
	/// <summary>
	/// RSA算法使用私钥解密 填充方式为RSA_PKCS1_OAEP_PADDING
	/// </summary>
	/// <param name="cipherText">密文</param>
	/// <param name="cipherTextLength">密文长度</param>
	/// <param name="plainText">解密后明文 传输NULL且返回true时，，使用完用户自己释放 delete[] plainText</param>
	/// <param name="plainTextLength">明文长度</param>
	/// <returns></returns>
	bool privateKeyDecrypt(unsigned char* cipherText, int cipherTextLength, unsigned char*& plainText, int& plainTextLength);

	/// <summary>
	/// RSA算法使用私钥加密 填充方式为RSA_PKCS1_PADDING
	/// </summary>
	/// <param name="plainText">明文 长度需小于等于RSA_SIZE-11字节</param>
	/// <param name="plainTextLength">明文长度</param>
	/// <param name="cipherText">密文 传输NULL且返回true时，，使用完需要释放,delete[] cipherText</param>
	/// <param name="cipherTextLength">密文长度</param>
	/// <returns></returns>
	bool privateKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength);
	/// <summary>
	/// RSA算法使用公钥解密 填充方式为RSA_PKCS1_PADDING
	/// </summary>
	/// <param name="cipherText">密文</param>
	/// <param name="cipherTextLength">密文长度</param>
	/// <param name="plainText">解密后明文 传输NULL且返回true时，，使用完用户自己释放 delete[] plainText</param>
	/// <param name="plainTextLength">明文长度</param>
	/// <returns></returns>
	bool publicKeyDecrypt(unsigned char* cipherText, int& cipherTextLength, unsigned char*& plainText, int& plainTextLength);

	size_t GetPubRsaSize() const
	{
		if(NULL != m_rsaPublic)
			return RSA_size(m_rsaPublic.get());

		return 0;
	}
	size_t GetPriRsaSize() const
	{
		if(NULL != m_rsaPrivate)
			return RSA_size(m_rsaPrivate.get());

		return 0;
	}

	// 当发生7和8错误的时候，调用该函数获得错误信息
	std::string GetEncrytOrDecryptInfo() const;

	bool Init();

	void Destory();
	~RsaEncryptor();

private:
	bool m_isInit;
	bool m_isUseEncrypt;
	bool m_isUseDecrypt;
	using RSAPtr = std::shared_ptr<RSA>;
	RSAPtr m_rsaPublic;
	RSAPtr m_rsaPrivate;
	unsigned long m_rsaErrorNo;
	void handleErrors();
	std::once_flag m_init_once_flag;
};


#endif
