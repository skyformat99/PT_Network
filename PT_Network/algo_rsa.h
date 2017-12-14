#ifndef ALGO_RSA_H
#define ALGO_RSA_H
#include <openssl/rsa.h>
/*
* openssl genrsa -des3 -out TradePrivate.key 2048   //����2048λ����RSA��Կ����Կ�ļ�ʹ��des3�㷨����
* openssl rsa -in TradePrivate.key -pubout -out TradePublic.key  //��Կ����,����ʱ����������������Կʱ������ͬ
*/
class AlogRSA
{
public:
	AlogRSA();
	~AlogRSA();
public:
	/// <summary>
	/// ����RSA��Կ
	/// </summary>
	/// <param name="path_public_key">��Կ�ļ�·��</param>
	/// <returns></returns>
	bool loadPublicKey(const char* path_public_key);
	/// <summary>
	/// ����RSA˽Կ
	/// </summary>
	/// <param name="path_private_key">˽Կ�ļ�·��</param>
	/// <param name="pem_password">˽Կ�ļ�������Կ</param>
	/// <returns></returns>
	bool loadPrivateKey(const char* path_private_key, const char* pem_password);
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

private:
	RSA* rsa_ctx_;
	static int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
	void handleErrors();
};
#endif //ALGO_RSA
