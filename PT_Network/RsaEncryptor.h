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
	/// RSA�㷨ʹ�ù�Կ���� ��䷽ʽΪRSA_PKCS1_OAEP_PADDING
	/// </summary>
	/// <param name="plainText">���� ������С�ڵ���RSA_SIZE-2 * SHA_DIGEST_LENGTH(20) - 2�ֽ�</param>
	/// <param name="plainTextLength">���ĳ���</param>
	/// <param name="cipherText">���� ����NULL�ҷ���trueʱ��ʹ������Ҫ�ͷ�,delete[] cipherText</param>
	/// <param name="cipherTextLength">���ĳ���</param>
	/// <returns></returns>
	bool publicKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength);
	/// <summary>
	/// RSA�㷨ʹ��˽Կ���� ��䷽ʽΪRSA_PKCS1_OAEP_PADDING
	/// </summary>
	/// <param name="cipherText">����</param>
	/// <param name="cipherTextLength">���ĳ���</param>
	/// <param name="plainText">���ܺ����� ����NULL�ҷ���trueʱ����ʹ�����û��Լ��ͷ� delete[] plainText</param>
	/// <param name="plainTextLength">���ĳ���</param>
	/// <returns></returns>
	bool privateKeyDecrypt(unsigned char* cipherText, int cipherTextLength, unsigned char*& plainText, int& plainTextLength);

	/// <summary>
	/// RSA�㷨ʹ��˽Կ���� ��䷽ʽΪRSA_PKCS1_PADDING
	/// </summary>
	/// <param name="plainText">���� ������С�ڵ���RSA_SIZE-11�ֽ�</param>
	/// <param name="plainTextLength">���ĳ���</param>
	/// <param name="cipherText">���� ����NULL�ҷ���trueʱ����ʹ������Ҫ�ͷ�,delete[] cipherText</param>
	/// <param name="cipherTextLength">���ĳ���</param>
	/// <returns></returns>
	bool privateKeyEncrypt(unsigned char* plainText, int plainTextLength, unsigned char*& cipherText, int& cipherTextLength);
	/// <summary>
	/// RSA�㷨ʹ�ù�Կ���� ��䷽ʽΪRSA_PKCS1_PADDING
	/// </summary>
	/// <param name="cipherText">����</param>
	/// <param name="cipherTextLength">���ĳ���</param>
	/// <param name="plainText">���ܺ����� ����NULL�ҷ���trueʱ����ʹ�����û��Լ��ͷ� delete[] plainText</param>
	/// <param name="plainTextLength">���ĳ���</param>
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

	// ������7��8�����ʱ�򣬵��øú�����ô�����Ϣ
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
