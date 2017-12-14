#include "algo_digest.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdlib.h>
AlgoDigest::AlgoDigest()
{
}


AlgoDigest::~AlgoDigest()
{
}

int AlgoDigest::Md5Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest)
{
	if(!digest)
	{
		digest = (unsigned char*)malloc(MD5_DIGEST_LENGTH);
	}

	MD5(plainText, plainTextLen, digest);
	return MD5_DIGEST_LENGTH;
}

int AlgoDigest::Sha1Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest)
{
	if(!digest)
	{
		digest = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
	}

	SHA1(plainText, plainTextLen, digest);
	return SHA_DIGEST_LENGTH;
}

int AlgoDigest::Sha256Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest)
{
	if(!digest)
	{
		digest = (unsigned char*) malloc(SHA256_DIGEST_LENGTH);
	}

	SHA256(plainText, plainTextLen, digest);
	return SHA256_DIGEST_LENGTH;
}

int AlgoDigest::Sha512Digest(unsigned char* plainText, int plainTextLen, unsigned char*& digest)
{
	if(!digest)
	{
		digest = (unsigned char*) malloc(SHA512_DIGEST_LENGTH);
	}

	SHA512(plainText, plainTextLen, digest);
	return SHA512_DIGEST_LENGTH;
}
