#ifndef _PT_UV_SP_SESSION_H_
#define _PT_UV_SP_SESSION_H_

#include "PT_Network.h"
#include "PT_UV_TcpSession.h"

using namespace PT_Network;

#define DEF_PT_MSG_RECVBUFF_SIZE    0xffffff              ///< 数据缓存buff长度
#define DEF_PT_MSG_BUFF_SIZE    0xfffff                  ///< 消息打包器buff长度

class PT_UV_SP_Session :
	public PT_UV_TcpSession,
	public PT_TCP_Session::PT_TCP_SessionCallBack
{
public:
#pragma pack(push)
#pragma pack(1)
	/**
	* @brief 数据包头
	*/
	struct PT_Msg_Header
	{
		int    nLen;                         ///< 正文  长度
	};
#pragma pack(pop)
public:
	PT_UV_SP_Session(PT_TCP_SessionCallBack* callback, PT_UV_Thread* recvThread);
	virtual ~PT_UV_SP_Session();
private:
	PT_TCP_SessionCallBack* m_cb;
	int                         nBuffSize;         ///< 缓存数据总长度
	void*                       szRecvBuffer;           ///< 数据缓存
	void*                       szSendBuffer;           ///< 数据缓存
public:     //回调
	void OnConnect();
	void OnClose();
	void OnSend(void* data, int err);
	void OnRecv(char* buf, size_t len);
	void OnErr(int err);
	void OnTimer(void* data);
	void OnStopTimer(void* data);
public:     //重写父类接口
	virtual PT_TCP_SessionCallBack* GetCallBack();
	virtual bool Connect(char* ip, int port);
	virtual void Shutdown();
	virtual bool Send(char* buf, size_t len, void* data);
	virtual int StartTimer(int timeout, int repeat, void* data);
	virtual void StopTimer(int timerId);

	virtual bool IsConnected();
	virtual void GetLocalAddr(char* ip, int ipLen, int& port);
	virtual void GetRemoteAddr(char* ip, int ipLen, int& port);

};

#endif

