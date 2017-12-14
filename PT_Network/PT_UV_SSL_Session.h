#ifndef _PT_UV_SSL_SESSION_H_
#define _PT_UV_SSL_SESSION_H_
#include "PT_Network.h"
#include "PT_UV_TcpSession.h"
#include "buffer_util.h"
#include "random.h"
#include "concurrentqueue.h"
#define HandShakeHeaderRndSize 512
#define HandleShakeOutTime 2000
#define AES_GCM_AAD_LEN 16
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16
#define AES_GCM_Extra_LEN 44
#define NormalMsgHeaderRndSize 10
#define SHA256_DIGEST_LEN 32
using namespace PT_Network;
#include "MBedRSA.h"
class PT_UV_SSL_Session :
	public PT_UV_TcpSession,
	public PT_TCP_Session::PT_TCP_SessionCallBack
{
public:
	/// <summary>
	///
	/// </summary>
	/// <param name="callback"></param>
	/// <param name="recvThread"></param>
	/// <param name="isServer"></param>
	/// <param name="pemFile">pem文件</param>
	/// <param name="pemFilePwd">pem文件秘钥</param>
	PT_UV_SSL_Session(PT_TCP_SessionCallBack* callback, PT_UV_Thread* recvThread, bool isServer);
	virtual ~PT_UV_SSL_Session();
private:
	PT_TCP_SessionCallBack* m_cb;
public:     //回调
	void OnConnect();
	void OnClose();
	void OnSend(void* data, int err) ;
	void OnRecv(char* buf, size_t len);
	void OnErr(int err);
	void OnTimer(void* arg);
	void OnStopTimer(void* data);
public:     //重写父类接口
	virtual PT_TCP_SessionCallBack* GetCallBack();
	virtual bool Connect(char* ip, int port);
	virtual bool Connect(char* ip, int port, int timeout);
	virtual void Shutdown();
	virtual bool Send(char* buf, size_t len, void* data);
	virtual int StartTimer(int timeout, int repeat, void* data);
	virtual void StopTimer(int timerId);

	virtual bool IsConnected();
	virtual void GetLocalAddr(char* ip, int ipLen, int& port);
	virtual void GetRemoteAddr(char* ip, int ipLen, int& port);
private:
	class SendArg
	{
	public:
		bool isInner;
		void* arg;
	};

	class TimerArg
	{
	public:
		bool isInner;
		bool isRepeated;
		void* arg;
	};
	bool m_isServer;
	int32_t m_connVerifyPhase;
	unsigned char m_aesKey[16];
	int32_t m_RndNumA;  //客户端随机数RA
	int32_t m_RndNumB; //服务器端随机数RB
	Buffer m_readBuffer;
	Random* m_randomGen;
	int m_timer_id;
#ifdef USE_MBEDTLS
	MBedRSA gMbedtlsRSA;
#endif
	enum ConnVerifyPhase
	{
		ConnVerifyPhase_Init = 1,
		ConnVerifyPhase_Hello1,
		ConnVerifyPhase_Hello2,
		ConnVerifyPhase_ConnVerified
	};

	enum MsgType
	{
		MsgType_Hello1 = 1,
		MsgType_Hello2,
		MsgType_ServerHello1,
		MsgType_ServerHello2,
		MsgType_KeyNegotiation,
		MsgType_NormalMessage
	};
#pragma pack(push,1)
	struct HandShakePacketHeader
	{
		int32_t packetLen;
		int32_t msgType;
		unsigned char rnd[HandShakeHeaderRndSize];
		int32_t rsaCipherLen;
	};

	struct NormalMessagePacketHeader
	{
		int32_t packetLen;
		int32_t msgType;
		unsigned char rndText[NormalMsgHeaderRndSize];
		int32_t cipherLen;   //int32_t seqNum + data
		int32_t aadLen;
		int32_t ivLen;
		int32_t tagLen;
		unsigned char aadData[AES_GCM_AAD_LEN];  //前缀附加数据
		unsigned char ivData[AES_GCM_IV_LEN];
		unsigned char tag[AES_GCM_TAG_LEN];
		unsigned char digest[SHA256_DIGEST_LEN];
	};
#pragma pack(pop)

private:
	void initRndNumA();
	void initRndNumB();
	void incrRndNumA();
	void incrRndNumB();
	int32_t getNextNum(int32_t num);
	void _Hello1();
	void _Hello2();
	void _serverHello1();
	void _serverHello2();
	void _keyNegotiation();
	bool onHello1(unsigned char* cipher, int32_t cipherLen);
	bool onHello2(unsigned char* cipher, int32_t cipherLen);
	bool onServerHello1(unsigned char* cipher, int32_t cipherLen);
	bool onServerHello2(unsigned char* cipher, int32_t cipherLen);
	bool onKeyNegotiation(unsigned char* cipher, int32_t cipherLen);
	bool onNormalMessage(int32_t packLen);
	int getRndNumInRange(int num);

};

#endif

