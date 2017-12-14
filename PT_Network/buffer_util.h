#ifndef BUFFER_JINQIU_H
#define BUFFER_JINQIU_H

#include "slice.h"
#include <algorithm>
#include <WinSock2.h>
#ifdef _WIN32
#pragma comment(lib,"ws2_32")
#endif // _WIN32

namespace PT_Network
{
	class  Buffer
	{
	public:
		static const size_t kCheapPrependSize;
		static const size_t kInitialSize;

		explicit Buffer(size_t initial_size = kInitialSize, size_t reserved_prepend_size = kCheapPrependSize)
			: capacity_(reserved_prepend_size + initial_size)
			, read_index_(reserved_prepend_size)
			, write_index_(reserved_prepend_size)
			, reserved_prepend_size_(reserved_prepend_size)
		{
			buffer_ = new char[capacity_];
			assert(length() == 0);
			assert(WritableBytes() == initial_size);
			assert(PrependableBytes() == reserved_prepend_size);
		}

		~Buffer()
		{
			delete[] buffer_;
			buffer_ = nullptr;
			capacity_ = 0;
		}

		void Swap(Buffer& rhs)
		{
			std::swap(buffer_, rhs.buffer_);
			std::swap(capacity_, rhs.capacity_);
			std::swap(read_index_, rhs.read_index_);
			std::swap(write_index_, rhs.write_index_);
			std::swap(reserved_prepend_size_, rhs.reserved_prepend_size_);
		}

		void Skip(size_t len)
		{
			if(len < length())
			{
				read_index_ += len;
			}
			else
			{
				Reset();
			}
		}

		void Retrieve(size_t len)
		{
			Skip(len);
		}

		void Truncate(size_t n)
		{
			if(n == 0)
			{
				read_index_ = reserved_prepend_size_;
				write_index_ = reserved_prepend_size_;
			}
			else if(write_index_ > read_index_ + n)
			{
				write_index_ = read_index_ + n;
			}
		}

		void Reset()
		{
			Truncate(0);
		}

		void Reserve(size_t len)
		{
			if(capacity_ >= len + reserved_prepend_size_)
			{
				return;
			}

			// TODO add the implementation logic here
			grow(len + reserved_prepend_size_);
		}

		void EnsureWritableBytes(size_t len)
		{
			if(WritableBytes() < len)
			{
				grow(len);
			}

			assert(WritableBytes() >= len);
		}

		void ToText()
		{
			AppendInt8('\0');
			UnwriteBytes(1);
		}

		// TODO XXX Little-Endian/Big-Endian problem.
#define bswap_64(x)                          \
    ((((x) & 0xff00000000000000ull) >> 56)       \
     | (((x) & 0x00ff000000000000ull) >> 40)     \
     | (((x) & 0x0000ff0000000000ull) >> 24)     \
     | (((x) & 0x000000ff00000000ull) >> 8)      \
     | (((x) & 0x00000000ff000000ull) << 8)      \
     | (((x) & 0x0000000000ff0000ull) << 24)     \
     | (((x) & 0x000000000000ff00ull) << 40)     \
     | (((x) & 0x00000000000000ffull) << 56))

		// Write
	public:
		void Write(const void* /*restrict*/ d, size_t len)
		{
			EnsureWritableBytes(len);
			memcpy(WriteBegin(), d, len);
			assert(write_index_ + len <= capacity_);
			write_index_ += len;
		}

		void Append(const Slice& str)
		{
			Write(str.data(), str.size());
		}

		void Append(const char* /*restrict*/ d, size_t len)
		{
			Write(d, len);
		}

		void Append(const void* /*restrict*/ d, size_t len)
		{
			Write(d, len);
		}

		void AppendInt64(__int64 x)
		{
			__int64 be = bswap_64(x);
			//__int64 be = htonll(x);
			Write(&be, sizeof be);
		}

		void AppendInt32(__int32 x)
		{
			__int32 be32 = htonl(x);
			Write(&be32, sizeof be32);
		}

		void AppendInt16(__int16 x)
		{
			__int16 be16 = htons(x);
			Write(&be16, sizeof be16);
		}

		void AppendInt8(__int8 x)
		{
			Write(&x, sizeof x);
		}

		void PrependInt64(__int64 x)
		{
			__int64 be = bswap_64(x);
			Prepend(&be, sizeof be);
		}

		void PrependInt32(__int32 x)
		{
			__int32 be32 = htonl(x);
			Prepend(&be32, sizeof be32);
		}

		void PrependInt16(__int16 x)
		{
			__int16 be16 = htons(x);
			Prepend(&be16, sizeof be16);
		}

		void PrependInt8(__int8 x)
		{
			Prepend(&x, sizeof x);
		}

		// Insert content, specified by the parameter, into the front of reading index
		void Prepend(const void* /*restrict*/ d, size_t len)
		{
			assert(len <= PrependableBytes());
			read_index_ -= len;
			const char* p = static_cast<const char*>(d);
			memcpy(begin() + read_index_, p, len);
		}

		void UnwriteBytes(size_t n)
		{
			assert(n <= length());
			write_index_ -= n;
		}

		void WriteBytes(size_t n)
		{
			assert(n <= WritableBytes());
			write_index_ += n;
		}

	public:
		__int64 ReadInt64()
		{
			__int64 result = PeekInt64();
			Skip(sizeof result);
			return result;
		}

		__int32 ReadInt32()
		{
			__int32 result = PeekInt32();
			Skip(sizeof result);
			return result;
		}

		__int16 ReadInt16()
		{
			__int16 result = PeekInt16();
			Skip(sizeof result);
			return result;
		}

		__int8 ReadInt8()
		{
			__int8 result = PeekInt8();
			Skip(sizeof result);
			return result;
		}

		Slice ToSlice() const
		{
			return Slice(data(), length());
		}

		std::string ToString() const
		{
			return std::string(data(), length());
		}

		void Shrink(size_t reserve)
		{
			Buffer other(length() + reserve);
			other.Append(ToSlice());
			Swap(other);
		}

		Slice Next(size_t len)
		{
			if(len < length())
			{
				Slice result(data(), len);
				read_index_ += len;
				return result;
			}

			return NextAll();
		}

		Slice NextAll()
		{
			Slice result(data(), length());
			Reset();
			return result;
		}

		std::string NextString(size_t len)
		{
			Slice s = Next(len);
			return std::string(s.data(), s.size());
		}

		std::string NextAllString()
		{
			Slice s = NextAll();
			return std::string(s.data(), s.size());
		}

		char ReadByte()
		{
			assert(length() >= 1);

			if(length() == 0)
			{
				return '\0';
			}

			return buffer_[read_index_++];
		}

		// UnreadBytes unreads the last n bytes returned
		// by the most recent read operation.
		void UnreadBytes(size_t n)
		{
			assert(n < read_index_);
			read_index_ -= n;
		}

	public:

		__int64 PeekInt64() const
		{
			assert(length() >= sizeof(__int64));
			__int64 be64 = 0;
			::memcpy(&be64, data(), sizeof be64);
			return bswap_64(be64);
		}

		__int32 PeekInt32() const
		{
			assert(length() >= sizeof(__int32));
			__int32 be32 = 0;
			::memcpy(&be32, data(), sizeof be32);
			return ntohl(be32);
		}

		__int16 PeekInt16() const
		{
			assert(length() >= sizeof(__int16));
			__int16 be16 = 0;
			::memcpy(&be16, data(), sizeof be16);
			return ntohs(be16);
		}

		__int8 PeekInt8() const
		{
			assert(length() >= sizeof(__int8));
			__int8 x = *data();
			return x;
		}

	public:
		const char* data() const
		{
			return buffer_ + read_index_;
		}

		char* WriteBegin()
		{
			return begin() + write_index_;
		}

		const char* WriteBegin() const
		{
			return begin() + write_index_;
		}

		size_t length() const
		{
			assert(write_index_ >= read_index_);
			return write_index_ - read_index_;
		}


		size_t size() const
		{
			return length();
		}

		size_t capacity() const
		{
			return capacity_;
		}

		size_t WritableBytes() const
		{
			assert(capacity_ >= write_index_);
			return capacity_ - write_index_;
		}

		size_t PrependableBytes() const
		{
			return read_index_;
		}

	public:
		const char* FindCRLF() const
		{
			const char* crlf = std::search(data(), WriteBegin(), kCRLF, kCRLF + 2);
			return crlf == WriteBegin() ? nullptr : crlf;
		}

		const char* FindCRLF(const char* start) const
		{
			assert(data() <= start);
			assert(start <= WriteBegin());
			const char* crlf = std::search(start, WriteBegin(), kCRLF, kCRLF + 2);
			return crlf == WriteBegin() ? nullptr : crlf;
		}

		const char* FindEOL() const
		{
			const void* eol = memchr(data(), '\n', length());
			return static_cast<const char*>(eol);
		}

		const char* FindEOL(const char* start) const
		{
			assert(data() <= start);
			assert(start <= WriteBegin());
			const void* eol = memchr(start, '\n', WriteBegin() - start);
			return static_cast<const char*>(eol);
		}
	private:

		char* begin()
		{
			return buffer_;
		}

		const char* begin() const
		{
			return buffer_;
		}

		void grow(size_t len)
		{
			if(WritableBytes() + PrependableBytes() < len + reserved_prepend_size_)
			{
				//grow the capacity
				size_t n = (capacity_ << 1) + len;
				size_t m = length();
				char* d = new char[n];
				memcpy(d + reserved_prepend_size_, begin() + read_index_, m);
				write_index_ = m + reserved_prepend_size_;
				read_index_ = reserved_prepend_size_;
				capacity_ = n;
				delete[] buffer_;
				buffer_ = d;
			}
			else
			{
				// move readable data to the front, make space inside buffer
				assert(reserved_prepend_size_ < read_index_);
				size_t readable = length();
				memmove(begin() + reserved_prepend_size_, begin() + read_index_, length());
				read_index_ = reserved_prepend_size_;
				write_index_ = read_index_ + readable;
				assert(readable == length());
				assert(WritableBytes() >= len);
			}
		}

	private:
		char* buffer_;
		size_t capacity_;
		size_t read_index_;
		size_t write_index_;
		size_t reserved_prepend_size_;
		static const char kCRLF[];
	};

}
#endif // ifndef