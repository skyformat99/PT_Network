#ifndef ALGO_DIGEST_H
#define ALGO_DIGEST_H
class AlgoDigest
{
public:
	AlgoDigest();
	~AlgoDigest();
	/// <summary>
	/// MD5摘要 16bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest">摘要</param>
	/// <returns>摘要长度（字节数）</returns>
	static int Md5Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);
	/// <summary>
	/// SHA-1摘要 20bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest"></param>
	/// <returns>摘要长度（字节数）</returns>
	static int Sha1Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);
	/// <summary>
	/// SHA256摘要 32bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest"></param>
	/// <returns>摘要长度（字节数）</returns>
	static int Sha256Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);
	/// <summary>
	/// SHA512摘要 64bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest"></param>
	/// <returns>摘要长度（字节数）</returns>
	static int Sha512Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);

};
#endif //ALGO_DIGEST_H

