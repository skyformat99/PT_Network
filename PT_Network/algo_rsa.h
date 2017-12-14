#ifndef ALGO_RSA_H
#define ALGO_RSA_H
#include <openssl/rsa.h>
/*
* openssl genrsa -des3 -out TradePrivate.key 2048   //生成2048位长的RSA秘钥，秘钥文件使用des3算法加密
* openssl rsa -in TradePrivate.key -pubout -out TradePublic.key  //公钥生成,生成时输入密码与生成密钥时密码相同
*/
class AlogRSA
{
public:
	AlogRSA();
	~AlogRSA();
public:
	/// <summary>
	/// 加载RSA公钥
	/// </summary>
	/// <param name="path_public_key">公钥文件路径</param>
	/// <returns></returns>
	bool loadPublicKey(const char* path_public_key);
	/// <summary>
	/// 加载RSA私钥
	/// </summary>
	/// <param name="path_private_key">私钥文件路径</param>
	/// <param name="pem_password">私钥文件加密秘钥</param>
	/// <returns></returns>
	bool loadPrivateKey(const char* path_private_key, const char* pem_password);
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

private:
	RSA* rsa_ctx_;
	static int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
	void handleErrors();
};
#endif //ALGO_RSA
