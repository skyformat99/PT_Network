#ifndef _PT_NETWORK_H_
#define _PT_NETWORK_H_

#ifdef PT_NETWORK_EXPORTS
#define PT_NETWORK_API __declspec(dllexport)
#else
#define PT_NETWORK_API __declspec(dllimport)
#endif
//#define  USE_MBEDTLS
namespace PT_Network
{
	void PT_NETWORK_API initOpenSSL(const char* pemFile, const char* pemFilePwd);
	const int Err_None = 0;
	const int Err_PIPE = -4047;
	const int Err_ConnReset = -4077;
	const int Err_ConnRefused = -4078;
	const int Err_Canceled = -4081;
	const int Err_EOF = -4095;
	const int Err_RecvBufOverFlow = -5000;

	enum SSLErrType
	{
		ErrType_PemFileErr = 1,
		ErrType_EncryptErr = 2,
		ErrType_DecryptErr = 3,
		ErrType_VerifyTimeout = 4,
		ErrType_VerifyErr = 5,
		ErrType_MsgTypeErr = 6,
		ErrType_IllegalIdentityErr = 7,
		ErrType_DataLengthErr = 8,
		ErrType_DataIntegrityErr = 9,
		ErrType_SendOverLengthErr = 10,
		ErrType_RecvSeqErr = 11,
	};

	//////////////////////////////////////////////////////////////////////////
	// 基础通信类
	//////////////////////////////////////////////////////////////////////////
	//链接类
	class PT_NETWORK_API PT_TCP_Session
	{
	public:
		class PT_TCP_SessionCallBack
		{
		public:
			virtual void OnConnect() = 0;
			virtual void OnClose() = 0;
			virtual void OnSend(void* data, int err) = 0;
			virtual void OnRecv(char* buf, size_t len) = 0;
			virtual void OnErr(int err) = 0;
			virtual void OnTimer(void* data) = 0;
			virtual void OnStopTimer(void* data) = 0;

			virtual ~PT_TCP_SessionCallBack() {};
		};
		virtual ~PT_TCP_Session() {};
	public:
		virtual PT_TCP_SessionCallBack* GetCallBack() = 0;
		virtual bool Connect(char* ip, int port, int timeout) = 0;          ///< timeout 为连接超时，单位毫秒，如果timeout时间内没有得到链接状态反馈即cancel本次链接操作  timeout=0时不启用超时检查
		virtual void Shutdown() = 0;                                        ///< 主动断开链接
		virtual bool Send(char* buff, size_t len, void* data) = 0;

		virtual bool IsConnected() = 0;
		virtual void GetLocalAddr(char* ip, int ipLen, int& port) = 0;
		virtual void GetRemoteAddr(char* ip, int ipLen, int& port) = 0;

		//以下两个Timer接口只可运行在回调线程中，否则不是线程安全的
		virtual int StartTimer(int timeout, int repeat, void* data) = 0;       ///< 启动定时器 timeout 时间后调用 OnTimer, repeat为0时回调只执行一次 单位毫秒, 多次调用会覆盖前一次的设置
		virtual void StopTimer(int timerId) = 0;                               ///< 关闭定时器


		static PT_TCP_Session* CreatUVSession(PT_TCP_SessionCallBack* callback);
		static PT_TCP_Session* CreatUVSessionSharedThread(PT_TCP_SessionCallBack* callback);
		static PT_TCP_Session* CreatUVSPSession(PT_TCP_SessionCallBack* callback);
		static PT_TCP_Session* CreatUVSPSessionSharedThread(PT_TCP_SessionCallBack* callback);
		static PT_TCP_Session* CreatUVSSLSession(PT_TCP_SessionCallBack* callback, bool isServer);
		static PT_TCP_Session* CreatUVSSLSessionSharedThread(PT_TCP_SessionCallBack* callback, bool isServer);
		static void RemoveUVSession(PT_TCP_Session* session);
	};

	//服务器类
	class PT_NETWORK_API PT_TCP_Server
	{
	public:
		class PT_TCP_ServerCallBack
		{
		public:
			virtual PT_TCP_Session* OnAccept() = 0;                         ///< 在该回调构造自己的session实例
			virtual void OnRemove(PT_TCP_Session* session) = 0;             ///< 在该回调安全析构session实例
			virtual ~PT_TCP_ServerCallBack() {};
		};
		virtual ~PT_TCP_Server() {};
	public:
		virtual PT_TCP_ServerCallBack* GetCallBack() = 0;
		virtual int Listen(char* ip, int port) = 0;
		virtual void Stop() = 0;

		static PT_TCP_Server* CreatUVServer(PT_TCP_ServerCallBack* callback);
		static PT_TCP_Server* CreatUVServerWithThreadPool(PT_TCP_ServerCallBack* callback, int threadNum);
		static void RemoveUVServer(PT_TCP_Server* server);
	};
	/*
	// 通信业务层
	class PT_NETWORK_API PT_APP_Session
	{
	public:
	    class PT_APP_SessionCallBack
	    {
	    public:
	        virtual void OnConnect() = 0;
	        virtual void OnClose() = 0;
	        virtual void OnSend(void* data, int err) = 0;
	        virtual void OnRecv(char* buf, size_t len) = 0;
	        virtual void OnErr(int err) = 0;
	    };
	public:
	    virtual ~PT_APP_Session() {}
	public:
	    virtual bool connect(char* ip, int port) = 0;
	    virtual void Shutdown() = 0;                                        ///< 主动断开链接
	    virtual void Send(char* buff, size_t len, void* data) = 0;

	    virtual bool IsConnected() = 0;
	    virtual void GetLocalAddr(char* ip, int ipLen, int& port) = 0;
	    virtual void GetRemoteAddr(char* ip, int ipLen, int& port) = 0;

	public:
	    static PT_APP_Session* CreateAppSession(PT_APP_SessionCallBack* callback, bool bSSL, int nReconnNum, bool bServer);
	    static PT_APP_Session* CreateAppSession(PT_APP_SessionCallBack* callback, bool bSSL, int nReconnNum);  // 默认为客户端
	};
	*/
}





#endif // DEBUG