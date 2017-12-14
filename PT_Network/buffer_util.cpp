#include "stdafx.h"
#include "buffer_util.h"
namespace PT_Network
{
	const char Buffer::kCRLF[] = "\r\n";
	const size_t Buffer::kCheapPrependSize = 8;
	const size_t Buffer::kInitialSize = 1024;
}