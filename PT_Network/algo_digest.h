#ifndef ALGO_DIGEST_H
#define ALGO_DIGEST_H
class AlgoDigest
{
public:
	AlgoDigest();
	~AlgoDigest();
	/// <summary>
	/// MD5ժҪ 16bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest">ժҪ</param>
	/// <returns>ժҪ���ȣ��ֽ�����</returns>
	static int Md5Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);
	/// <summary>
	/// SHA-1ժҪ 20bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest"></param>
	/// <returns>ժҪ���ȣ��ֽ�����</returns>
	static int Sha1Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);
	/// <summary>
	/// SHA256ժҪ 32bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest"></param>
	/// <returns>ժҪ���ȣ��ֽ�����</returns>
	static int Sha256Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);
	/// <summary>
	/// SHA512ժҪ 64bytes
	/// </summary>
	/// <param name="plainText"></param>
	/// <param name="plainTextLen"></param>
	/// <param name="digest"></param>
	/// <returns>ժҪ���ȣ��ֽ�����</returns>
	static int Sha512Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest);

};
#endif //ALGO_DIGEST_H

