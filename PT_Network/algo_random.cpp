#include "algo_random.h"
#include <openssl/rand.h>
#include <string>
AlgoRandom::AlgoRandom()
{
}


AlgoRandom::~AlgoRandom()
{
}

void AlgoRandom::RAND_add_secure_240bits(const void* buf, int num, double entropy)
{
	int n = 1023;
	const unsigned char dummy_seed[20] = { 0 };

	if(buf)
	{
		RAND_add(buf, num, entropy);
	}

	while(n > 0)
	{
		RAND_add(dummy_seed, sizeof(dummy_seed), 0.0);
		n -= sizeof(dummy_seed);
	}
}

void AlgoRandom::RAND_add_secure_256bits(const void* buf, int num, double entropy)
{
	RAND_add_secure_240bits(buf, num, entropy);
	RAND_add_secure_240bits(NULL, 0, 0.0);
}

void AlgoRandom::RAND_seed_secure_240bits(const void *buf, int num)
{
	RAND_add_secure_240bits(buf, num, (double)num);
}

void AlgoRandom::RAND_seed_secure_256bits(const void *buf, int num)
{
	RAND_add_secure_256bits(buf, num, (double)num);
}

int AlgoRandom::RAND_poll_secure_240bits()
{
	int result = RAND_poll();
	RAND_add_secure_240bits(NULL, 0, 0.0);
	return result;
}

int AlgoRandom::RAND_poll_secure_256bits()
{
	int result = RAND_poll();
	RAND_add_secure_256bits(NULL, 0, 0.0);
	return result;
}

int AlgoRandom::RAND_load_file_secure_240bits(const char *file, long max_bytes)
{
	int ret = RAND_load_file(file, max_bytes);
	RAND_add_secure_240bits(NULL, 0, 0.0);
	return ret;
}

int AlgoRandom::RAND_load_file_secure_256bits(const char *file, long max_bytes)
{
	int ret = RAND_load_file(file, max_bytes);
	RAND_add_secure_256bits(NULL, 0, 0.0);
	return ret;
}

int AlgoRandom::RAND_bytes_secure(unsigned char *buf, int num)
{
	memset(buf, 0, num);
	int final_ret = 1;

	while(num)
	{
		int ret;
		int this_round = num > 10 ? 10 : num;
		ret = RAND_bytes(buf, this_round);

		if(ret != 1)
		{
			final_ret = ret;
		}

		buf += this_round;
		num -= this_round;
	}

	return final_ret;
}

int AlgoRandom::RAND_pseudo_bytes_secure(unsigned char *buf, int num)
{
	memset(buf, 0, num);
	return RAND_pseudo_bytes(buf, num);
}
