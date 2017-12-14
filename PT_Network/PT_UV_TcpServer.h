#ifndef _PT_UV_TCPSERVER_H_
#define _PT_UV_TCPSERVER_H_
#include "PT_Network.h"

using namespace PT_Network;
#include <set>
#include "PT_UV_Thread.h"
#include "PT_UV_TcpSession.h"

class PT_UV_TcpServer : public PT_TCP_Server
{
public:
	PT_UV_TcpServer(PT_TCP_ServerCallBack* callBack);
	PT_UV_TcpServer(PT_TCP_ServerCallBack* callBack, int threadNum);
	virtual ~PT_UV_TcpServer();

private:
	PT_TCP_ServerCallBack* m_callBack;				//回调对象
	PT_UV_Thread* t_tcp;							//tcp 工作线程
	uv_tcp_t* m_tcpHandle;
	PT_UV_ThreadPool* t_pool;						//回调线程池
	std::set<PT_UV_TcpSession*> m_sessionSet;		//session 集合
private:
	void init(PT_TCP_ServerCallBack* callBack, int threadNum);
public:
	PT_TCP_ServerCallBack* GetCallBack();
	int Listen(char* ip, int port);					//监听全部网卡为 "0.0.0.0"
	void Stop();
	void removeSession(PT_UV_TcpSession* session);
public:
	static void on_connection(uv_stream_t* server, int status);
	static void on_removeSession(uv_async_t* handle);
	static void on_close_handle(uv_handle_t* handle);
};

#endif	//_PT_UV_TCPSERVER_H_