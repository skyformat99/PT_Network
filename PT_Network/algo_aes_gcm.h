#ifndef ALGO_AES_GCM_H
#define ALGO_AES_GCM_H
class AlgoAesGcm
{
public:
	AlgoAesGcm();
	~AlgoAesGcm();
	/// <summary>
	/// 生成随机128位秘钥
	/// </summary>
	/// <param name="key"></param>
	/// <returns></returns>
	static bool genAesRandomKey(unsigned char*& key);
	/// <summary>
	/// AES加密 操作模式：EVP_aes_128_gcm
	/// plainText、plainTextLen、key 输入参数
	/// aad、iv、cipherText、tag传入NULL，且返回true时需要delete[]释放
	/// </summary>
	/// <param name="plainText">明文</param>
	/// <param name="plainTextLen">明文长度</param>
	/// <param name="key">秘钥</param>
	/// <param name="aad">前缀附加数据 默认16字节</param>
	/// <param name="addLen">前缀附加数据长度</param>
	/// <param name="iv">初始矩阵，内部使用随机数进行填充</param>
	/// <param name="ivLen">初始矩阵长度</param>
	/// <param name="cipherText">加密后密文</param>
	/// <param name="cipherTextLen">密文长度</param>
	/// <param name="tag">验证标签 16字节</param>
	/// <returns>true:加密正确  false:加密错误</returns>
	static bool encrypt(unsigned char* plainText, int plainTextLen,
						unsigned char* key,
						unsigned char*& aad, int& addLen,
						unsigned char*& iv, int& ivLen,
						unsigned char*& cipherText, int& cipherTextLen,
						unsigned char*& tag);
	/// <summary>
	/// AES解密 操作模式：EVP_aes_128_gcm
	/// </summary>
	/// <param name="cipherText">密文</param>
	/// <param name="cipherTextLen">密文长度</param>
	/// <param name="key">秘钥</param>
	/// <param name="aad">前缀附加数据</param>
	/// <param name="aadLen">前缀附加数据长度</param>
	/// <param name="tag">验证标签</param>
	/// <param name="iv">初始矩阵</param>
	/// <param name="ivLen">初始矩阵长度</param>
	/// <param name="plainText">解密后明文</param>
	/// <param name="plainTextLen">明文长度</param>
	/// <returns></returns>
	static bool decrypt(unsigned char *cipherText, int cipherTextLen,
						unsigned char *key,
						unsigned char *aad, int aadLen,
						unsigned char *tag,
						unsigned char *iv, int ivLen,
						unsigned char*& plainText, int& plainTextLen);
private:
	static void handleErrors();
};
#endif
