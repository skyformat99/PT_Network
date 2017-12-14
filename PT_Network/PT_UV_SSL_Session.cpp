#include "PT_UV_SSL_Session.h"
#include "algo_random.h"
#include "algo_rsa.h"
#include "algo_aes_gcm.h"
#include "algo_digest.h"
#include <iostream>
#include <thread>
#include "RsaEncryptor.h"
#include "MBedRSA.h"
const int endian = 1;
#define is_bigendian() ( (*(char*) &endian) == 0 )
#define is_littlendbian() ( (*(char*) &endian) == 1 )
#define OffsetType_MsgType offsetof(HandShakePacketHeader,msgType)
#define BUFF_MAX_LEN 0xFFFF

#ifndef USE_MBEDTLS
extern RsaEncryptor gEncryptor;
#else
//extern thread_local MBedRSA  gMbedtlsRSA;
#endif // !USE_MBEDTLS


int32_t asInt32(const char* buf)
{
	int32_t be32 = 0;
	::memcpy(&be32, buf, sizeof(be32));
	return ntohl(be32);
}

PT_UV_SSL_Session::PT_UV_SSL_Session(PT_TCP_SessionCallBack* callback, PT_UV_Thread* recvThread, bool isServer)
	: PT_UV_TcpSession(this, recvThread),
	  m_isServer(isServer),
	  m_connVerifyPhase(ConnVerifyPhase::ConnVerifyPhase_Init),
	  m_timer_id(-1)
{

	m_cb = callback;

	if(isServer)
	{
		//初始化服务端随机数RB
		m_RndNumB = 0;
		AlgoRandom::RAND_bytes_secure(((unsigned char*)&m_RndNumB), 3);
		m_randomGen = new Random(m_RndNumB);
		std::cout << "m_RndNumB = " << m_RndNumB << std::endl;
#ifdef USE_MBEDTLS
		gMbedtlsRSA.setPrivateKeyFile("F:\\QuantPlatform\\PT_Network\\TradePrivate.key", "qihui1402");
#endif // USE_MBEDTLS


	}
	else
	{
		//初始化客户端随机数RA
		m_RndNumA = 0;
		AlgoRandom::RAND_bytes_secure(((unsigned char*)&m_RndNumA), 3);
		m_randomGen = new Random(m_RndNumA);
		std::cout << "m_RndNumA = " << m_RndNumA << std::endl;
#ifdef USE_MBEDTLS
		gMbedtlsRSA.setPublicKeyFile("F:\\QuantPlatform\\PT_Network\\TradePublic.key");
#endif
	}
}


PT_UV_SSL_Session::~PT_UV_SSL_Session()
{
	delete m_randomGen;
}

//////////////////////////////////////////////////////////////////////////
// 回调
void PT_UV_SSL_Session::OnConnect()
{
	std::cout << "PT_UV_SSL_Session::OnConnect()" << std::endl;

	if(!m_isServer)
	{
		//客户端
		_Hello1();
	}
	else
	{
		//服务器端
		TimerArg* arg = new TimerArg;
		arg->isRepeated = false;
		arg->isInner = true;
		arg->arg = (void*)ConnVerifyPhase::ConnVerifyPhase_Init;
		m_timer_id = startTimer(HandleShakeOutTime, 0, arg);
	}

}

void PT_UV_SSL_Session::OnClose()
{
	if(m_cb)
	{
		m_cb->OnClose();
	}
}

void PT_UV_SSL_Session::OnSend(void* data, int err)
{
	if(!data)
	{
		return;


	}

	SendArg* arg = (SendArg*)data;

	if(arg->isInner)
	{
	}
	else
	{
		if(m_cb)
		{
			m_cb->OnSend(arg->arg, err);
		}
	}

	delete arg;
	arg = NULL;
}

//拼包
void PT_UV_SSL_Session::OnRecv(char* buf, size_t len)
{

	// 实现拼包
	m_readBuffer.Append(buf, len);
	bool ret = true;

	while(ret && m_readBuffer.length() >= sizeof(int32_t))
	{

		int32_t packLen = asInt32(m_readBuffer.data());

		if(m_readBuffer.length() >= packLen)
		{

			int32_t msgType = asInt32(m_readBuffer.data() + sizeof(int32_t));


			if(msgType < MsgType_Hello1)
			{
				//消息类别错误
				OnErr(ErrType_MsgTypeErr);
				shutdown();
				ret = false;
			}

			if(msgType >= MsgType_NormalMessage)
			{

				ret = onNormalMessage(packLen);

				//递增seq
				if(m_isServer)
				{
					incrRndNumB();
				}
				else
				{
					incrRndNumA();
				}
			}
			else
			{
				//读取packLen
				m_readBuffer.ReadInt32();
				//读取msgType
				m_readBuffer.ReadInt32();
				//跳过512字节随机数
				m_readBuffer.Retrieve(HandShakeHeaderRndSize);
				int32_t cipherLen = m_readBuffer.ReadInt32();

				if(cipherLen + sizeof(HandShakePacketHeader) != packLen)
				{
					OnErr(SSLErrType::ErrType_DataLengthErr);
					shutdown();
					ret = false;
					break;
				}

				unsigned char* cipher = (unsigned char*)m_readBuffer.data();

				switch(msgType)
				{
					case MsgType_Hello1:
						ret = onHello1(cipher, cipherLen);
						break;

					case  MsgType_Hello2:
						ret = onHello2(cipher, cipherLen);
						break;

					case MsgType_ServerHello1:
						ret = onServerHello1(cipher, cipherLen);
						break;

					case MsgType_ServerHello2:
						ret = onServerHello2(cipher, cipherLen);
						break;

					case MsgType_KeyNegotiation:
						ret = onKeyNegotiation(cipher, cipherLen);
						break;
				}

				//readIndex+密文长度
				m_readBuffer.Retrieve(cipherLen);
			}
		}
	}

}

bool PT_UV_SSL_Session::onNormalMessage(int32_t packLen)
{
	//未通过验证
	if(m_connVerifyPhase != ConnVerifyPhase::ConnVerifyPhase_ConnVerified)
	{
		OnErr(SSLErrType::ErrType_IllegalIdentityErr);
		shutdown();
		return false;
	}

	//packLen长度小于包头+序列号长度
	if(packLen < sizeof(NormalMessagePacketHeader) + sizeof(int32_t))
	{
		OnErr(SSLErrType::ErrType_DataLengthErr);
		shutdown();
		return false;
	}

	//跳过NormalMsgHeaderRndSize个字节
	//m_readBuffer.Retrieve(NormalMsgHeaderRndSize);
	int32_t cipherLen = asInt32(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, cipherLen));
	int32_t aadLen = asInt32(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, aadLen));;
	int32_t ivLen = asInt32(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, ivLen));;
	int32_t tagLen = asInt32(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, tagLen));;

	if(cipherLen + sizeof(NormalMessagePacketHeader) != packLen)
	{
		OnErr(SSLErrType::ErrType_DataLengthErr);
		shutdown();
		return false;
	}

	unsigned char* aadData = (unsigned char*)(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, aadData));
	unsigned char* ivData = (unsigned char*)(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, ivData));
	unsigned char* tag = (unsigned char*)(m_readBuffer.data() + offsetof(NormalMessagePacketHeader, tag));
	unsigned char* cipher = tag + AES_GCM_TAG_LEN;
	unsigned char* digest = cipher + cipherLen;
	unsigned char* plainText = NULL;
	int plainLen = 0;
	//解密数据
	bool ret = AlgoAesGcm::decrypt(cipher, cipherLen,
								   m_aesKey,
								   aadData, AES_GCM_AAD_LEN,
								   tag,
								   ivData, AES_GCM_IV_LEN,
								   plainText, plainLen);

	if(!ret)
	{
		OnErr(SSLErrType::ErrType_DecryptErr);
		free(cipher);
		return false;
	}

	unsigned char* sha256Digest = NULL;
	//SHA256验证
	AlgoDigest::Sha256Digest((unsigned char*)m_readBuffer.data(), packLen - SHA256_DIGEST_LEN, sha256Digest);

	if(memcmp(sha256Digest, digest, SHA256_DIGEST_LEN) != 0)
	{
		free(plainText);
		OnErr(SSLErrType::ErrType_DataIntegrityErr);
		shutdown();
		return false;
	}

	m_readBuffer.Retrieve(packLen);
	int32_t seq = asInt32((const char*)plainText);
	int32_t wantToVerSeq = 0;

	if(m_isServer)
	{
		wantToVerSeq = m_RndNumB;
	}
	else
	{
		wantToVerSeq = m_RndNumA;
	}


	if(seq != wantToVerSeq)
	{
		free(plainText);
		OnErr(SSLErrType::ErrType_RecvSeqErr);
		shutdown();
		return false;
	}


	if(m_cb)
	{
		m_cb->OnRecv((char*)plainText + sizeof(int32_t), plainLen - sizeof(int32_t));
	}

	free(plainText);
	return true;
}

void PT_UV_SSL_Session::OnErr(int err)
{
	if(m_cb)
	{
		m_cb->OnErr(err);
	}
};

void PT_UV_SSL_Session::OnTimer(void* arg)
{
	if(!arg)
	{
		return;
	}

	TimerArg* timeArg = (TimerArg*)arg;

	if(timeArg->isInner)
	{
		int32_t phase = (int32_t)(timeArg->arg);


		if(m_connVerifyPhase > phase)
		{
			return;
		}

		OnErr(ErrType_VerifyTimeout);
		shutdown();
	}
	else
	{
		if(m_cb)
		{
			m_cb->OnTimer(timeArg->arg);
		}
	}

	//delete timeArg;
}

void PT_UV_SSL_Session::OnStopTimer(void* data)
{

	if(!data)
	{
		return;
	}

	TimerArg* timeArg = (TimerArg*)data;
	//std::cout << "OnStopTimer " << (int32_t)timeArg->arg;

	if(timeArg->isInner)
	{

	}
	else
	{
		if(m_cb)
		{
			m_cb->OnStopTimer(timeArg->arg);
		}
	}

	delete timeArg;
}
//////////////////////////////////////////////////////////////////////////
// 重写父类接口
PT_TCP_Session::PT_TCP_SessionCallBack* PT_UV_SSL_Session::GetCallBack()
{
	return m_cb;
}

bool PT_UV_SSL_Session::Connect(char* ip, int port)
{
	return connect(ip, port, 0);
}

bool PT_UV_SSL_Session::Connect(char* ip, int port, int timeout)
{
	return connect(ip, port, timeout);
}

void PT_UV_SSL_Session::Shutdown()
{
	shutdown();
}

bool PT_UV_SSL_Session::Send(char* buf, size_t len, void* data)
{
	//Header|seq|buf
	if(len + sizeof(int32_t) + sizeof(NormalMessagePacketHeader) > BUFF_MAX_LEN)
	{
		OnErr(SSLErrType::ErrType_SendOverLengthErr);
		return false;
	}

	////////////////////////
	// 上层应用发送明文数据，对数据进行加密封包
	////////////////////////
	unsigned char* aad = NULL;
	int aadLen = AES_GCM_AAD_LEN;
	unsigned char* iv = NULL;
	int ivLen = AES_GCM_IV_LEN;
	unsigned char* cipher = NULL;
	int cipherLen = 0;
	unsigned char* tag = NULL;
	Buffer writeBuf;

	if(m_isServer)
	{
		writeBuf.AppendInt32(getNextNum(m_RndNumA));
		incrRndNumA();
	}
	else
	{
		writeBuf.AppendInt32(getNextNum(m_RndNumB));
		incrRndNumB();

	}

	writeBuf.Append(buf, len);


	bool ret = AlgoAesGcm::encrypt((unsigned char*)writeBuf.data(), writeBuf.length(),
								   m_aesKey,
								   aad, aadLen,
								   iv, ivLen,
								   cipher, cipherLen,
								   tag);

	if(!ret)
	{
		OnErr(SSLErrType::ErrType_EncryptErr);

		return false;
	}

	aadLen = getRndNumInRange(AES_GCM_AAD_LEN);
	ivLen = getRndNumInRange(AES_GCM_IV_LEN);
	int tagLen = AES_GCM_Extra_LEN - aadLen - ivLen;

	unsigned char rndText[NormalMsgHeaderRndSize] = {0};
	AlgoRandom::RAND_bytes_secure(rndText, NormalMsgHeaderRndSize);
	//清空writebuf
	writeBuf.Reset();
	writeBuf.AppendInt32(MsgType::MsgType_NormalMessage);
	writeBuf.Append(rndText, NormalMsgHeaderRndSize);
	writeBuf.AppendInt32(cipherLen);
	writeBuf.AppendInt32(aadLen);
	writeBuf.AppendInt32(ivLen);
	writeBuf.AppendInt32(tagLen);
	writeBuf.Append(aad, AES_GCM_AAD_LEN);
	writeBuf.Append(iv, AES_GCM_IV_LEN);
	writeBuf.Append(tag, AES_GCM_TAG_LEN);
	writeBuf.Append(cipher, cipherLen);
	writeBuf.PrependInt32(writeBuf.length() + sizeof(int32_t) + SHA256_DIGEST_LEN);
	unsigned char* sha256Digest = (unsigned char*)malloc(SHA256_DIGEST_LEN);
	//计算摘要
	AlgoDigest::Sha256Digest((unsigned char*)writeBuf.data(), writeBuf.length(), sha256Digest);
	writeBuf.Append(sha256Digest, SHA256_DIGEST_LEN);

	//清理内存
	free(aad);
	free(iv);
	free(tag);
	free(cipher);
	free(sha256Digest);
	SendArg* arg = new SendArg;
	arg->isInner = false;
	arg->arg = data;
	ret = send((char*)writeBuf.data(), writeBuf.length(), arg);

	if(!ret)
	{
		delete arg;
	}

	return ret;
}

int PT_UV_SSL_Session::StartTimer(int timeout, int repeat, void* data)
{
	if(m_connVerifyPhase != ConnVerifyPhase::ConnVerifyPhase_ConnVerified)
	{
		return 0;
	}

	TimerArg* arg = new TimerArg;
	arg->isInner = false;

	if(repeat > 0)
	{
		arg->isRepeated = true;
	}

	arg->arg = data;
	return startTimer(timeout, repeat, arg);
}

void PT_UV_SSL_Session::StopTimer(int timerId)
{
	if(m_connVerifyPhase != ConnVerifyPhase::ConnVerifyPhase_ConnVerified)
	{
		return;
	}

	stopTimer(timerId);
}

bool PT_UV_SSL_Session::IsConnected()
{
	return isConnected();
}

void PT_UV_SSL_Session::GetLocalAddr(char* ip, int ipLen, int& port)
{
	return getLocalAddr(ip, ipLen, port);
}

void PT_UV_SSL_Session::GetRemoteAddr(char* ip, int ipLen, int& port)
{
	getRemoteAddr(ip, ipLen, port);
}

void PT_UV_SSL_Session::initRndNumA()
{
	m_RndNumA = 0;

	if(is_bigendian())
	{
		AlgoRandom::RAND_bytes_secure(((unsigned char*)&m_RndNumA), 3);
	}
	else
	{
		AlgoRandom::RAND_bytes_secure(((unsigned char*)&m_RndNumA) + 1, 3);
	}
}

void PT_UV_SSL_Session::initRndNumB()
{
	m_RndNumB = 0;

	if(is_bigendian())
	{
		AlgoRandom::RAND_bytes_secure(((unsigned char*)&m_RndNumB), 3);
	}
	else
	{
		AlgoRandom::RAND_bytes_secure(((unsigned char*)&m_RndNumB) + 1, 3);
	}

}

void PT_UV_SSL_Session::incrRndNumA()
{
	if(m_RndNumA >= INT32_MAX)
	{
		m_RndNumA = 0;
	}
	else
	{
		++m_RndNumA;
	}
}

void PT_UV_SSL_Session::incrRndNumB()
{
	if(m_RndNumB >= INT32_MAX)
	{
		m_RndNumB = 0;
	}
	else
	{
		++m_RndNumB;
	}
}

int32_t PT_UV_SSL_Session::getNextNum(int32_t num)
{
	if(num >= INT32_MAX)
	{
		return 0;
	}
	else
	{
		return num + 1;
	}
}

/************************************************************************/
/*            握手信息                                                   */
/************************************************************************/
void PT_UV_SSL_Session::_Hello1()
{
	std::cout << " PT_UV_SSL_Session::_Hello1()" << std::endl;
	//客户端发送  公钥加密随机数[RA]

	do
	{
		HandShakePacketHeader msg;
		//生成512字节随机数
		AlgoRandom::RAND_bytes_secure(msg.rnd, sizeof(msg.rnd));
		//msgType设置
		msg.msgType = MsgType::MsgType_Hello1;


		unsigned char* cipher = NULL;
		//客户端Hello1阶段对RndNumA使用公钥加密
		int32_t numSend = htonl(m_RndNumA);
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.publicKeyEncrypt((unsigned char*)&numSend, sizeof(numSend), cipher, msg.rsaCipherLen);
#else
		ret = gEncryptor.publicKeyEncrypt((unsigned char*)&numSend, sizeof(numSend), cipher, msg.rsaCipherLen);
#endif // USE_MBEDTLS



		if(!ret)
		{
			OnErr(ErrType_EncryptErr);
			break;
		}

		msg.packetLen = sizeof(msg) + msg.rsaCipherLen;
		Buffer m_writeBuffer;
		m_writeBuffer.AppendInt32(msg.msgType);
		m_writeBuffer.Append(msg.rnd, sizeof(msg.rnd));
		m_writeBuffer.AppendInt32(msg.rsaCipherLen);
		m_writeBuffer.Append(cipher, msg.rsaCipherLen);
		//Prepend 总长度
		m_writeBuffer.PrependInt32(m_writeBuffer.length() + sizeof(int32_t));
		free(cipher);
		SendArg* sendArg = new SendArg;
		sendArg->isInner = true;
		sendArg->arg = NULL;
		send((char*)m_writeBuffer.data(), m_writeBuffer.length(), sendArg);
		m_connVerifyPhase = ConnVerifyPhase::ConnVerifyPhase_Hello1;
		//启动定时器
		TimerArg* arg = new TimerArg;
		arg->isRepeated = false;
		arg->isInner = true;
		arg->arg = (void*)ConnVerifyPhase::ConnVerifyPhase_Hello1;
		m_timer_id = startTimer(HandleShakeOutTime, 0, arg);
		return;
	}
	while(0);

	//断开连接
	shutdown();
}

bool PT_UV_SSL_Session::onHello1(unsigned char* cipher, int32_t cipherLen)
{
	std::cout << " PT_UV_SSL_Session::onHello1()" << std::endl;

	//收到客户端发送的[RA]加密数据
	do
	{


		unsigned char* plainText = NULL;
		int32_t plainLen = 0;
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.privateKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#else
		ret = gEncryptor.privateKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(SSLErrType::ErrType_DecryptErr);
			break;
		}

		if(plainLen < sizeof(int32_t))
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			free(plainText);
			break;
		}

		//记录客户端的RA
		m_RndNumA = asInt32((char*)plainText);
		std::cout << "m_RndNumA= " << m_RndNumA << std::endl;
		free(plainText);
		//ServerHello1()
		_serverHello1();
		return true;

	}
	while(0);

	shutdown();
	return false;


}

void PT_UV_SSL_Session::_serverHello1()
{
	std::cout << " PT_UV_SSL_Session::_serverHello1()" << std::endl;

	//服务器端发送 私钥加密随机数[RA RB]
	do
	{
		HandShakePacketHeader msg;
		//生成512字节随机数
		AlgoRandom::RAND_bytes_secure(msg.rnd, sizeof(msg.rnd));
		//msgType设置
		msg.msgType = MsgType::MsgType_ServerHello1;


		unsigned char* cipher = NULL;
		int32_t numSendA = htonl(m_RndNumA);
		int32_t numSendB = htonl(m_RndNumB);
		unsigned char buf[sizeof(numSendA) + sizeof(numSendB)] = { 0 };  //[RA,RB]
		memcpy_s(buf, sizeof(numSendA), &numSendA, sizeof(numSendA));
		memcpy_s(buf + sizeof(numSendA), sizeof(numSendB), &numSendB, sizeof(numSendB));
		//客户端Hello1阶段对RndNumA使用公钥加密
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.privateKeyEncrypt(buf, sizeof(numSendB) + sizeof(numSendA), cipher, msg.rsaCipherLen);
#else
		ret = gEncryptor.privateKeyEncrypt(buf, sizeof(numSendB) + sizeof(numSendA), cipher, msg.rsaCipherLen);
#endif // USE_MBEDTLS

		if(!ret)
		{
			OnErr(ErrType_EncryptErr);
			break;
		}

		msg.packetLen = sizeof(msg) + msg.rsaCipherLen;
		Buffer m_writeBuffer;
		m_writeBuffer.AppendInt32(msg.msgType);
		m_writeBuffer.Append(msg.rnd, sizeof(msg.rnd));
		m_writeBuffer.AppendInt32(msg.rsaCipherLen);
		m_writeBuffer.Append(cipher, msg.rsaCipherLen);
		//Prepend 总长度
		m_writeBuffer.PrependInt32(m_writeBuffer.length() + sizeof(int32_t));
		free(cipher);
		SendArg* sendArg = new SendArg;
		sendArg->isInner = true;
		sendArg->arg = NULL;
		send((char*)m_writeBuffer.data(), m_writeBuffer.length(), sendArg);
		m_connVerifyPhase = ConnVerifyPhase::ConnVerifyPhase_Hello1;
		//启动定时器
		TimerArg* arg = new TimerArg;
		arg->isRepeated = false;
		arg->isInner = true;
		arg->arg = (void*)ConnVerifyPhase::ConnVerifyPhase_Hello1;
		m_timer_id = startTimer(HandleShakeOutTime, 0, arg);
		return;
	}
	while(0);

	//断开连接
	shutdown();
}

bool PT_UV_SSL_Session::onServerHello1(unsigned char* cipher, int32_t cipherLen)
{
	std::cout << " PT_UV_SSL_Session::onServerHello1()" << std::endl;

	//收到服务端发送的[RA RB]加密数据
	do
	{


		unsigned char* plainText = NULL;
		int32_t plainLen = 0;
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.publicKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#else
		ret = gEncryptor.publicKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(SSLErrType::ErrType_DecryptErr);
			break;
		}

		if(plainLen < sizeof(m_RndNumA) + sizeof(m_RndNumB))
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			free(plainText);
			break;
		}

		//记录客户端的RA
		int32_t recvRndA = asInt32((char*)plainText);
		m_RndNumB = asInt32((char*)plainText + sizeof(m_RndNumA));
		free(plainText);

		if(recvRndA == m_RndNumA)
		{
			_keyNegotiation();
			//_Hello2();
			return true;
		}
		else
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			return false;
		}
	}
	while(0);

	shutdown();
	return false;

}

void PT_UV_SSL_Session::_Hello2()
{
	std::cout << " PT_UV_SSL_Session::_Hello2()" << std::endl;

	//公钥加密随机数[RB RA]
	do
	{
		HandShakePacketHeader msg;
		//生成512字节随机数
		AlgoRandom::RAND_bytes_secure(msg.rnd, sizeof(msg.rnd));
		//msgType设置
		msg.msgType = MsgType::MsgType_Hello2;


		unsigned char* cipher = NULL;
		int32_t numSendA = htonl(m_RndNumA);
		int32_t numSendB = htonl(m_RndNumB);
		unsigned char buf[sizeof(numSendA) + sizeof(numSendA)] = { 0 }; // //[RB,RA]
		memcpy_s(buf, sizeof(numSendB), &numSendB, sizeof(numSendB));
		memcpy_s(buf + sizeof(numSendB), sizeof(numSendA), &numSendA, sizeof(numSendA));
		//客户端Hello1阶段对RndNumA使用公钥加密
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.publicKeyEncrypt(buf, sizeof(numSendA) + sizeof(numSendA), cipher, msg.rsaCipherLen);
#else
		ret = gEncryptor.publicKeyEncrypt(buf, sizeof(numSendA) + sizeof(numSendA), cipher, msg.rsaCipherLen);
#endif // USE_MBEDTLS

		if(!ret)
		{
			OnErr(ErrType_EncryptErr);
			break;
		}

		msg.packetLen = sizeof(msg) + msg.rsaCipherLen;
		Buffer m_writeBuffer;
		m_writeBuffer.AppendInt32(msg.msgType);
		m_writeBuffer.Append(msg.rnd, sizeof(msg.rnd));
		m_writeBuffer.AppendInt32(msg.rsaCipherLen);
		m_writeBuffer.Append(cipher, msg.rsaCipherLen);
		//Prepend 总长度
		m_writeBuffer.PrependInt32(m_writeBuffer.length() + sizeof(int32_t));
		free(cipher);
		SendArg* sendArg = new SendArg;
		sendArg->isInner = true;
		sendArg->arg = NULL;
		send((char*)m_writeBuffer.data(), m_writeBuffer.length(), sendArg);
		//加入sendinfo缓冲队列

		//启动定时器
		m_connVerifyPhase = ConnVerifyPhase::ConnVerifyPhase_Hello2;
		TimerArg* arg = new TimerArg;
		arg->isRepeated = false;
		arg->isInner = true;
		arg->arg = (void*)ConnVerifyPhase::ConnVerifyPhase_Hello2;
		m_timer_id = startTimer(HandleShakeOutTime, 0, arg);
		return;
	}
	while(0);

	//断开连接
	shutdown();
}

bool PT_UV_SSL_Session::onHello2(unsigned char* cipher, int32_t cipherLen)
{
	std::cout << " PT_UV_SSL_Session::onHello2()" << std::endl;

	//收到客户端发送的[RB RA]加密数据
	do
	{


		unsigned char* plainText = NULL;
		int32_t plainLen = 0;
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.privateKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#else
		ret = gEncryptor.privateKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(SSLErrType::ErrType_DecryptErr);
			break;
		}

		if(plainLen < sizeof(m_RndNumA) + sizeof(m_RndNumB))
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			free(plainText);
			break;
		}


		int32_t recvRndB = asInt32((char*)plainText);
		int32_t recvRndA = asInt32((char*)plainText + sizeof(m_RndNumA));
		free(plainText);

		if(recvRndA == m_RndNumA && recvRndB == m_RndNumB)
		{
			_serverHello2();
			return true;
		}
		else
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			return false;
		}
	}
	while(0);

	shutdown();
	return false;
}

void PT_UV_SSL_Session::_serverHello2()
{
	std::cout << " PT_UV_SSL_Session::_serverHello2()" << std::endl;

	//私钥加密数据 RA+RB
	do
	{
		HandShakePacketHeader msg;
		//生成512字节随机数
		AlgoRandom::RAND_bytes_secure(msg.rnd, sizeof(msg.rnd));
		//msgType设置
		msg.msgType = MsgType::MsgType_ServerHello2;

		unsigned char* cipher = NULL;
		int64_t sum = m_RndNumA;
		sum += m_RndNumB;

		sum = bswap_64(sum);

		//客户端Hello1阶段对RndNumA使用公钥加密
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.privateKeyEncrypt((unsigned char*)&sum, sizeof(sum), cipher, msg.rsaCipherLen);
#else
		ret = gEncryptor.privateKeyEncrypt((unsigned char*)&sum, sizeof(sum), cipher, msg.rsaCipherLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(ErrType_EncryptErr);
			break;
		}

		msg.packetLen = sizeof(msg) + msg.rsaCipherLen;
		Buffer m_writeBuffer;
		m_writeBuffer.AppendInt32(msg.msgType);
		m_writeBuffer.Append(msg.rnd, sizeof(msg.rnd));
		m_writeBuffer.AppendInt32(msg.rsaCipherLen);
		m_writeBuffer.Append(cipher, msg.rsaCipherLen);
		//Prepend 总长度
		m_writeBuffer.PrependInt32(m_writeBuffer.length() + sizeof(int32_t));
		free(cipher);
		SendArg* sendArg = new SendArg;
		sendArg->isInner = true;
		sendArg->arg = NULL;
		send((char*)m_writeBuffer.data(), m_writeBuffer.length(), sendArg);
		m_connVerifyPhase = ConnVerifyPhase::ConnVerifyPhase_Hello2;
		TimerArg* arg = new TimerArg;
		arg->isRepeated = false;
		arg->isInner = true;
		arg->arg = (void*)ConnVerifyPhase::ConnVerifyPhase_Hello2;
		m_timer_id = startTimer(HandleShakeOutTime, 0, arg);
		return;
	}
	while(0);

	//断开连接
	shutdown();
}


bool PT_UV_SSL_Session::onServerHello2(unsigned char* cipher, int32_t cipherLen)
{
	std::cout << " PT_UV_SSL_Session::onServerHello2()" << std::endl;

	do
	{

		unsigned char* plainText = NULL;
		int32_t plainLen = 0;
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.publicKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#else
		ret = gEncryptor.publicKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(SSLErrType::ErrType_DecryptErr);
			break;
		}

		if(plainLen < sizeof(int64_t))
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			free(plainText);
			break;
		}


		int64_t recvSum = 0;
		::memcpy(&recvSum, plainText, sizeof recvSum);
		recvSum = bswap_64(recvSum);
		free(plainText);
		int64_t sum = m_RndNumA;
		sum += m_RndNumB;

		if(recvSum == sum)
		{
			_keyNegotiation();
			return true;
		}
		else
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			return false;
		}
	}
	while(0);

	shutdown();
	return false;
}

void PT_UV_SSL_Session::_keyNegotiation()
{
	std::cout << " PT_UV_SSL_Session::_keyNegotiation()" << std::endl;

	//秘钥协商 客户端使用公钥加密发送随机秘钥
	do
	{
		HandShakePacketHeader msg;
		//生成512字节随机数
		AlgoRandom::RAND_bytes_secure(msg.rnd, sizeof(msg.rnd));
		//msgType设置
		msg.msgType = MsgType::MsgType_KeyNegotiation;

		//随机初始化m_aesKey
		AlgoRandom::RAND_bytes_secure(m_aesKey, sizeof(m_aesKey));
		unsigned char* cipher = NULL;
		//客户端Hello1阶段对RndNumA使用公钥加密
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.publicKeyEncrypt(m_aesKey, sizeof(m_aesKey), cipher, msg.rsaCipherLen);
#else
		ret = gEncryptor.publicKeyEncrypt(m_aesKey, sizeof(m_aesKey), cipher, msg.rsaCipherLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(ErrType_EncryptErr);
			break;
		}

		msg.packetLen = sizeof(msg) + msg.rsaCipherLen;
		Buffer m_writeBuffer;
		m_writeBuffer.AppendInt32(msg.msgType);
		m_writeBuffer.Append(msg.rnd, sizeof(msg.rnd));
		m_writeBuffer.AppendInt32(msg.rsaCipherLen);
		m_writeBuffer.Append(cipher, msg.rsaCipherLen);
		//Prepend 总长度
		m_writeBuffer.PrependInt32(m_writeBuffer.length() + sizeof(int32_t));
		free(cipher);
		SendArg* sendArg = new SendArg;
		sendArg->isInner = true;
		sendArg->arg = NULL;
		send((char*)m_writeBuffer.data(), m_writeBuffer.length(), sendArg);
		m_connVerifyPhase = ConnVerifyPhase::ConnVerifyPhase_ConnVerified;
		stopTimer(m_timer_id);
		//客户端递增seq
		incrRndNumA();

		if(m_cb)
		{
			m_cb->OnConnect();
		}

		return;
	}
	while(0);

	//断开连接
	shutdown();
}

bool PT_UV_SSL_Session::onKeyNegotiation(unsigned char* cipher, int32_t cipherLen)
{
	std::cout << " PT_UV_SSL_Session::onKeyNegotiation()" << std::endl;

	do
	{


		unsigned char* plainText = NULL;
		int32_t plainLen = 0;
		bool ret = true;
#ifdef USE_MBEDTLS
		ret = gMbedtlsRSA.privateKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#else
		ret = gEncryptor.privateKeyDecrypt(cipher, cipherLen, plainText, plainLen);
#endif // USE_MBEDTLS


		if(!ret)
		{
			OnErr(SSLErrType::ErrType_DecryptErr);
			break;
		}

		if(plainLen < sizeof(m_aesKey))
		{
			OnErr(SSLErrType::ErrType_VerifyErr);
			free(plainText);

			break;
		}


		memcpy_s(m_aesKey, sizeof(m_aesKey), plainText, sizeof(m_aesKey));
		free(plainText);

		m_connVerifyPhase = ConnVerifyPhase::ConnVerifyPhase_ConnVerified;
		stopTimer(m_timer_id);
		//服务器端递增
		incrRndNumB();

		if(m_cb)
		{
			m_cb->OnConnect();
		}

		return true;
	}
	while(0);

	shutdown();
	return false;
}

int PT_UV_SSL_Session::getRndNumInRange(int num)
{
	return m_randomGen->Uniform(num);
}