#ifndef _PT_UV_TCPSESSION_H_
#define _PT_UV_TCPSESSION_H_
#include "PT_Network.h"

// #define _CRTDBG_MAP_ALLOC
// #include <stdlib.h>
// #include <crtdbg.h>

using namespace PT_Network;
#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <list>
#include "concurrentqueue.h"
#include "PT_UV_Thread.h"

class PT_UV_TcpServer;
class PT_UV_TcpSession : public PT_TCP_Session
{
private:
	struct SendInfo
	{
		uv_buf_t buf;
		void* data;
	};
	struct WriteInfo {
		uv_write_t* req;
		int status;
		long bufNum;
		PT_UV_TcpSession* session;
		uv_buf_t* buf;
		void** data;
	};
	struct TimerInfo {
		static std::atomic<int> gId;
		int id;
		int timeout;
		int repeat;
		void* data;
		PT_UV_TcpSession* session;
		uv_timer_t* timer;
	};
	struct StopTimerInfo {
		int id;
		PT_UV_TcpSession* session;
	};
	struct RecvMsg
	{
		enum MsgType
		{
			// 回调消息
			MsgType_onConnect	= 1,
			MsgType_onClose		= 2,
			MsgType_onRead		= 3,
			MsgType_onWrite		= 4,
			MsgType_onErr		= 5,
			MsgType_onTimer		= 6,
			MsgType_onStopTimer = 7,
		};

		MsgType nType;
		int nInt;
		void* data;

		static RecvMsg* GetConnectMsg();
		static RecvMsg* GetCloseMsg();
		static RecvMsg* GetReadMsg(uv_buf_t* buf);
		static RecvMsg* GetWriteMsg(WriteInfo* info);
		static RecvMsg* GetErrMsg(int err);
		static RecvMsg* GetTimerMsg(TimerInfo* info);
		static RecvMsg* GetStopTimerMsg(TimerInfo* info);
	};
public:
	PT_UV_TcpSession(PT_TCP_SessionCallBack* callBack, PT_UV_Thread* recvThread);
	virtual ~PT_UV_TcpSession();
public:
	static PT_UV_Thread* g_recv;                //共享 回调处理线程
private:
	PT_TCP_SessionCallBack* m_callBack;         //回调对象
	sockaddr_in m_addr;                         //链接地址
	std::atomic<bool> bIsConnected;             //链接状态
	std::atomic<bool> bIsCheckingConnected;     //检查链接状态
	
	PT_UV_Thread* t_recv;                       //回调处理线程
	uv_async_t* s_recv;
	moodycamel::ConcurrentQueue<RecvMsg*> q_recv;

	PT_UV_Thread* t_tcp;                        //tcp IO线程
	uv_tcp_t* m_tcpHandle;                      //tcp 处理对象
	uv_async_t* s_send;
	moodycamel::ConcurrentQueue<SendInfo*> q_send;
	std::list<WriteInfo*> m_writingList;		//发送中的消息

	//timer容器
	std::list<TimerInfo*> m_timerList;
	
	PT_UV_TcpServer* m_server;
private:
	void init(PT_UV_Thread* tcpThread, PT_UV_Thread* recvThread);           //设置线程
	void syncSend(char* buf, size_t len, void* data);       //只能执行在Tcp线程中，否则线程不安全直接返回
	void emitRecv(RecvMsg* msg);
public:
	// 附加接口
	void accpet(uv_stream_t* server, PT_UV_Thread* tcpThread, PT_UV_Thread* recvThread);
	PT_UV_TcpServer* getServer();
protected:
	// 工具方法
	void sendError(int err);
	bool serverModel();                         //是否是服务端模式，false 为客户端模式
	// 接口实现
	PT_TCP_SessionCallBack* getCallBack();
	bool connect(char* ip, int port, int timeout);
	void shutdown();
	bool send(char* buf, size_t len, void* data);
	int startTimer(int timeout, int repeat, void* data);
	void stopTimer(int timerId);

	bool isConnected();
	void getLocalAddr(char* ip, int ipLen, int& port);
	void getRemoteAddr(char* ip, int ipLen, int& port);
public:
	// 定义接口
	virtual PT_TCP_SessionCallBack* GetCallBack();
	virtual bool Connect(char* ip, int port, int timeout);
	virtual void Shutdown();
	virtual bool Send(char* buf, size_t len, void* data);
	virtual int StartTimer(int timeout, int repeat, void* data);
	virtual void StopTimer(int timerId);

	virtual bool IsConnected();
	virtual void GetLocalAddr(char* ip, int ipLen, int& port);
	virtual void GetRemoteAddr(char* ip, int ipLen, int& port);
private:        // 全局静态函数
	//tcp相关回调       //执行在tcp线程
	static void on_connection(uv_connect_t* handle, int status);
	static void on_connectTimeout(uv_timer_t* handle);
	static void on_shutdown(uv_shutdown_t* req, int status);
	static void on_write(uv_write_t* req, int status);
	static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
	static void on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);
	//发送线程回调
	static void onSend(uv_async_t* handle);

	//回调线程通知回调		//执行在回调线程
	void OnConnectMsg();
	void OnCloseMsg();
	void OnReadMsg(uv_buf_t* buf);
	void OnWriteMsg(WriteInfo* info);
	void OnErrMsg(int err);
	void OnTimerMsg(TimerInfo* info);
	void OnStopTimerMsg(TimerInfo* info);
	void handleRecvMsg(RecvMsg* msg);
	static void onRecvMsg(uv_async_t* handle);
	
	//timer tcp线程回调
	static void onStartTimer(uv_async_t* handle);
	static void onCloseTimer(uv_async_t* handle);
	static void onTimer(uv_timer_t* handle);

	//关闭handle
	void closeSendHandle();
	void closeTcpHandle();
	void closeRecvHandle();
	void closeAllTimer();	//仅运行在tcp线程
	void clearWritingList();
	static void on_closeSendHandle(uv_handle_t* handle);
	static void on_closeTcpHandle(uv_handle_t* handle);
	static void on_closeRecvHandle(uv_handle_t* handle);
	static void on_close_handle(uv_handle_t* handle);

	

};



#endif  //_PT_UV_TCPSESSION_H_