#ifndef ALGO_AES_GCM_H
#define ALGO_AES_GCM_H
class AlgoAesGcm
{
public:
	AlgoAesGcm();
	~AlgoAesGcm();
	/// <summary>
	/// �������128λ��Կ
	/// </summary>
	/// <param name="key"></param>
	/// <returns></returns>
	static bool genAesRandomKey(unsigned char*& key);
	/// <summary>
	/// AES���� ����ģʽ��EVP_aes_128_gcm
	/// plainText��plainTextLen��key �������
	/// aad��iv��cipherText��tag����NULL���ҷ���trueʱ��Ҫdelete[]�ͷ�
	/// </summary>
	/// <param name="plainText">����</param>
	/// <param name="plainTextLen">���ĳ���</param>
	/// <param name="key">��Կ</param>
	/// <param name="aad">ǰ׺�������� Ĭ��16�ֽ�</param>
	/// <param name="addLen">ǰ׺�������ݳ���</param>
	/// <param name="iv">��ʼ�����ڲ�ʹ��������������</param>
	/// <param name="ivLen">��ʼ���󳤶�</param>
	/// <param name="cipherText">���ܺ�����</param>
	/// <param name="cipherTextLen">���ĳ���</param>
	/// <param name="tag">��֤��ǩ 16�ֽ�</param>
	/// <returns>true:������ȷ  false:���ܴ���</returns>
	static bool encrypt(unsigned char* plainText, int plainTextLen,
						unsigned char* key,
						unsigned char*& aad, int& addLen,
						unsigned char*& iv, int& ivLen,
						unsigned char*& cipherText, int& cipherTextLen,
						unsigned char*& tag);
	/// <summary>
	/// AES���� ����ģʽ��EVP_aes_128_gcm
	/// </summary>
	/// <param name="cipherText">����</param>
	/// <param name="cipherTextLen">���ĳ���</param>
	/// <param name="key">��Կ</param>
	/// <param name="aad">ǰ׺��������</param>
	/// <param name="aadLen">ǰ׺�������ݳ���</param>
	/// <param name="tag">��֤��ǩ</param>
	/// <param name="iv">��ʼ����</param>
	/// <param name="ivLen">��ʼ���󳤶�</param>
	/// <param name="plainText">���ܺ�����</param>
	/// <param name="plainTextLen">���ĳ���</param>
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
