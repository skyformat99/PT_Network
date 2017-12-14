#ifndef ALGO_BASE64_H
#define ALGO_BASE64_H
class AlgoBase64
{
public:
	AlgoBase64();
	~AlgoBase64();
	/// <summary>
	/// BASE64加密
	/// cipherText传输NULL时，需要使用delete[] cipherText 进行释放
	/// cipherText传输非NULL值时，注意开辟足够长度
	/// </summary>
	/// <param name="plainText">明文</param>
	/// <param name="plainTextLen">明文长度</param>
	/// <param name="cipherText">密文</param>
	/// <param name="cipherLen">密文数据实际长度</param>
	/// <param name="with_new_line">密文数据是否换行</param>
	static void  Base64Encode(unsigned char*plainText, int plainTextLen, unsigned char*& cipherText, int& cipherLen, bool with_new_line = false);
	/// <summary>
	/// BASE64解密
	/// plainText传输NULL时，需要使用delete[] plainText进行释放
	/// plainText传输非NULL值时，注意开辟足够长度
	/// </summary>
	/// <param name="cipherText">密文</param>
	/// <param name="cipherLen">密文长度</param>
	/// <param name="plainText">解密后明文</param>
	/// <param name="plainTextLen">解密后明文长度</param>
	/// <param name="with_new_line">密文数据是否换行</param>
	static void  Base64Decode(unsigned char*cipherText, int cipherLen, unsigned char*& plainText, int& plainTextLen, bool with_new_line = false);

};
#endif


