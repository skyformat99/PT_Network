#ifndef ALGO_BASE64_H
#define ALGO_BASE64_H
class AlgoBase64
{
public:
	AlgoBase64();
	~AlgoBase64();
	/// <summary>
	/// BASE64����
	/// cipherText����NULLʱ����Ҫʹ��delete[] cipherText �����ͷ�
	/// cipherText�����NULLֵʱ��ע�⿪���㹻����
	/// </summary>
	/// <param name="plainText">����</param>
	/// <param name="plainTextLen">���ĳ���</param>
	/// <param name="cipherText">����</param>
	/// <param name="cipherLen">��������ʵ�ʳ���</param>
	/// <param name="with_new_line">���������Ƿ���</param>
	static void  Base64Encode(unsigned char*plainText, int plainTextLen, unsigned char*& cipherText, int& cipherLen, bool with_new_line = false);
	/// <summary>
	/// BASE64����
	/// plainText����NULLʱ����Ҫʹ��delete[] plainText�����ͷ�
	/// plainText�����NULLֵʱ��ע�⿪���㹻����
	/// </summary>
	/// <param name="cipherText">����</param>
	/// <param name="cipherLen">���ĳ���</param>
	/// <param name="plainText">���ܺ�����</param>
	/// <param name="plainTextLen">���ܺ����ĳ���</param>
	/// <param name="with_new_line">���������Ƿ���</param>
	static void  Base64Decode(unsigned char*cipherText, int cipherLen, unsigned char*& plainText, int& plainTextLen, bool with_new_line = false);

};
#endif


