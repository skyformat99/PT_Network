#ifndef ALGO_RANDOM_H
#define ALGO_RANDOM_H

class AlgoRandom
{
public:
	AlgoRandom();
	~AlgoRandom();
public:
	/// <summary>
	/// 初始化随机数种子
	/// </summary>
	/// <returns></returns>
	static int RAND_poll_secure_240bits();
	/// <summary>
	/// 初始化随机数种子
	/// </summary>
	/// <returns></returns>
	static int RAND_poll_secure_256bits();
	/// <summary>
	/// 随机数
	/// </summary>
	/// <param name="buf"></param>
	/// <param name="num"></param>
	/// <returns></returns>
	static int RAND_bytes_secure(unsigned char *buf, int num);
	/// <summary>
	/// 随机数
	/// </summary>
	/// <param name="buf"></param>
	/// <param name="num"></param>
	/// <returns></returns>
	static int RAND_pseudo_bytes_secure(unsigned char *buf, int num);
private:
	static void RAND_add_secure_240bits(const void* buf, int num, double entropy);
	static void RAND_add_secure_256bits(const void* buf, int num, double entropy);
	static void RAND_seed_secure_240bits(const void *buf, int num);
	static void RAND_seed_secure_256bits(const void *buf, int num);
	static int RAND_load_file_secure_240bits(const char *file, long max_bytes);
	static int RAND_load_file_secure_256bits(const char *file, long max_bytes);

};
#endif
