#include "PT_UV_TcpSession.h"
#include "PT_UV_TcpServer.h"

//////////////////////////////////////////////////////////////////////////
// TimerInfo
//////////////////////////////////////////////////////////////////////////
std::atomic<int> PT_UV_TcpSession::TimerInfo::gId = 0;
//////////////////////////////////////////////////////////////////////////
// RecvMsg
//////////////////////////////////////////////////////////////////////////
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetConnectMsg()
{
	PT_UV_TcpSession::RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onConnect;
	msg->nInt = 0;
	msg->data = NULL;
	return msg;
}
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetCloseMsg()
{
	RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onClose;
	msg->nInt = 0;
	msg->data = NULL;
	return msg;
}
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetReadMsg(uv_buf_t* buf)
{
	RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onRead;
	msg->nInt = 0;
	msg->data = buf;
	return msg;
}
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetWriteMsg(WriteInfo* info)
{
	RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onWrite;
	msg->nInt = 0;
	msg->data = info;
	return msg;
}
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetErrMsg(int err)
{
	RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onErr;
	msg->nInt = err;
	msg->data = NULL;
	return msg;
}
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetTimerMsg(TimerInfo* info)
{
	RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onTimer;
	msg->nInt = 0;
	msg->data = info;
	return msg;
}
PT_UV_TcpSession::RecvMsg* PT_UV_TcpSession::RecvMsg::GetStopTimerMsg(TimerInfo* info)
{
	RecvMsg* msg = (RecvMsg*)malloc(sizeof(RecvMsg));
	msg->nType = RecvMsg::MsgType_onStopTimer;
	msg->nInt = 0;
	msg->data = info;
	return msg;
}
//////////////////////////////////////////////////////////////////////////
// PT_UV_TcpSession
//////////////////////////////////////////////////////////////////////////
#define _BUFF_MAX_LEN_ 0xFFFF
#define _LOCKFREEQUEUE_SIZE_ 10000
#define _SESSION_PRINT_INFO_ 1

PT_UV_Thread* PT_UV_TcpSession::g_recv = NULL;                  //共享 回调处理线程

PT_UV_TcpSession::PT_UV_TcpSession(PT_TCP_SessionCallBack* callBack, PT_UV_Thread* recvThread)
{
	m_callBack = callBack;
	bIsConnected = false;
	bIsCheckingConnected = false;

	t_recv = recvThread;
	s_recv = NULL;

	t_tcp = NULL;
	m_tcpHandle = NULL;
	s_send = NULL;

	m_server = NULL;
}

PT_UV_TcpSession::~PT_UV_TcpSession()
{
	//_CrtDumpMemoryLeaks();
};
//////////////////////////////////////////////////////////////////////////
//  私有函数
void PT_UV_TcpSession::init(PT_UV_Thread* tcpThread, PT_UV_Thread* recvThread)
{
	if(!t_tcp)
	{
		t_tcp = tcpThread ? tcpThread : (new PT_UV_Thread);
	}

	if(!t_recv)
	{
		t_recv = recvThread ? recvThread : (new PT_UV_Thread);
	}

	g_recv = g_recv ? g_recv : t_recv;

	if(!m_tcpHandle)
	{
		m_tcpHandle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		memset(m_tcpHandle, 0, sizeof(uv_tcp_t));
		uv_tcp_init(t_tcp->loop(), m_tcpHandle);
		//uv_stream_set_blocking((uv_stream_t*)m_tcpHandle, 1);
		m_tcpHandle->data = this;
	}

	bIsConnected = false;
	bIsCheckingConnected = false;

	//回调信号
	if(!s_recv)
	{
		s_recv = (uv_async_t*)malloc(sizeof(uv_async_t));
		memset(s_recv, 0, sizeof(uv_async_t));
		s_recv->data = this;
		uv_async_init(t_recv->loop(), s_recv, PT_UV_TcpSession::onRecvMsg);
	}

	//发送信号
	if(!s_send)
	{
		s_send = (uv_async_t*)malloc(sizeof(uv_async_t));
		memset(s_send, 0, sizeof(uv_async_t));
		s_send->data = this;
		uv_async_init(t_tcp->loop(), s_send, PT_UV_TcpSession::onSend);
	}

}
// tcp 线程函数
void PT_UV_TcpSession::syncSend(char* buf, size_t len, void* data)
{
	uv_thread_t currentThread = uv_thread_self();

	if(t_tcp->isSameThread(currentThread))
	{
		WriteInfo* info = (WriteInfo*)malloc(sizeof(WriteInfo));
		info->status = 0;
		info->session = this;
		info->bufNum = 1;
		info->buf = (uv_buf_t*)malloc(sizeof(uv_buf_t));
		info->data = (void**)malloc(sizeof(void*));

		info->buf->len = len;
		info->buf->base = (char*)malloc(info->buf->len);
		memcpy(info->buf->base, buf, info->buf->len);
		memcpy(info->data, data, sizeof(void*));

		uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
		req->data = info;
		uv_write(req, (uv_stream_t *)m_tcpHandle, info->buf, info->bufNum, PT_UV_TcpSession::on_write);
	}
	else
	{
		printf("Send abort, this function syncSend must be called in tcp thread \n");
	}
}
void PT_UV_TcpSession::emitRecv(RecvMsg* msg)
{
	q_recv.enqueue(msg);
	uv_async_send(s_recv);
}
//////////////////////////////////////////////////////////////////////////
// 附加接口
void PT_UV_TcpSession::accpet(uv_stream_t* server,
							  PT_UV_Thread* tcpThread, PT_UV_Thread* recvThread)
{
	init(tcpThread, recvThread);

	if(m_callBack)
	{
		int r = uv_accept(server, (uv_stream_t*)m_tcpHandle);

		if(r == 0)
		{
			uv_read_start((uv_stream_t*)m_tcpHandle,
						  PT_UV_TcpSession::on_alloc,
						  PT_UV_TcpSession::on_read);
			bIsConnected = true;
			m_server = (PT_UV_TcpServer*)server->data;
			t_recv->run();
			t_tcp->run();
		}
		else
		{
			printf("accpet err: %s\n", uv_err_name(r));
		}
	}
	else
	{
		printf("There is no callBack obj, stop accpet\n");
	}
}
PT_UV_TcpServer* PT_UV_TcpSession::getServer()
{
	return m_server;
}
//////////////////////////////////////////////////////////////////////////
// 工具方法
void PT_UV_TcpSession::sendError(int err)
{
	RecvMsg* msg = RecvMsg::GetErrMsg(err);
	emitRecv(msg);
}
bool PT_UV_TcpSession::serverModel()
{
	if(m_server)
	{
		return true;
	}
	else
	{
		return false;
	}
}
// 对外接口实现
PT_TCP_Session::PT_TCP_SessionCallBack* PT_UV_TcpSession::getCallBack()
{
	return m_callBack;
}
bool PT_UV_TcpSession::connect(char* ip, int port, int timeout)
{
	if(t_tcp)
	{
		t_tcp->join();
	}

	init(NULL, NULL);

	if(m_callBack)
	{
		uv_connect_t* req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
		req->data = this;

		uv_ip4_addr(ip, port, &m_addr);
		uv_tcp_init(t_tcp->loop(), m_tcpHandle);
		int r = uv_tcp_connect(req,
							   m_tcpHandle,
							   (const struct sockaddr*)&m_addr,
							   PT_UV_TcpSession::on_connection);

		if(timeout)
		{
			uv_timer_t* connectTimer = (uv_timer_t*)malloc(sizeof(uv_timer_t));
			connectTimer->data = this;
			uv_timer_init(t_tcp->loop(), connectTimer);
			uv_timer_start(connectTimer,
						   PT_UV_TcpSession::on_connectTimeout,
						   timeout, 0);
		}

		t_recv->run();
		t_tcp->run();
		bIsCheckingConnected = true;

		while(bIsCheckingConnected);

		return bIsConnected;
	}
	else
	{
		printf("There is no callBack obj, stop connect\n");
		return false;
	}
}
void PT_UV_TcpSession::shutdown()
{
	if(bIsConnected)
	{
		uv_read_stop((uv_stream_t*)m_tcpHandle);
		uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(uv_shutdown_t));
		req->data = this;
		int r = uv_shutdown(req, (uv_stream_t*)m_tcpHandle, PT_UV_TcpSession::on_shutdown);
//		t_tcp->cleanNeedCloseHandle();
	}
}
bool PT_UV_TcpSession::send(char* buf, size_t len, void* data)
{
	if(!bIsConnected)
	{
		printf("Send: Con not send buf when the seession is disconnected \n");
		return false;
	}

	uv_thread_t currentThread = uv_thread_self();

	if(t_tcp->isSameThread(currentThread))
	{
		syncSend(buf, len, data);
	}
	else
	{
		if(len > 0)
		{
			SendInfo* info = (SendInfo*)malloc(sizeof(SendInfo));
			info->buf.base = (char*)malloc(len);
			info->buf.len = len;
			info->data = data;
			memcpy(info->buf.base, buf, len);
			q_send.enqueue(info);
			uv_async_send(s_send);
		}
		else if(len == 0)
		{
			uv_async_send(s_send);
		}
	}

	return true;
}
int PT_UV_TcpSession::startTimer(int timeout, int repeat, void* data)
{
	if(!bIsConnected)
	{
		return 0;
	}

	TimerInfo* info = (TimerInfo*)malloc(sizeof(TimerInfo));
	info->id = TimerInfo::gId++;
	info->timeout = timeout;
	info->repeat = repeat;
	info->data = data;
	info->session = this;
	info->timer = (uv_timer_t*)malloc(sizeof(uv_timer_t));
	info->timer->data = info;

	uv_async_t* req = (uv_async_t*)malloc(sizeof(uv_async_t));
	req->data = info;
	uv_async_init(t_tcp->loop(), req, PT_UV_TcpSession::onStartTimer);
	uv_async_send(req);
	return info->id;
}
void PT_UV_TcpSession::stopTimer(int timerId)
{
	if(!bIsConnected)
	{
		return;
	}

	StopTimerInfo* info = (StopTimerInfo*)malloc(sizeof(StopTimerInfo));
	info->id = timerId;
	info->session = this;

	uv_async_t* req = (uv_async_t*)malloc(sizeof(uv_async_t));
	req->data = info;
	uv_async_init(t_tcp->loop(), req, PT_UV_TcpSession::onCloseTimer);
	uv_async_send(req);
}
bool PT_UV_TcpSession::isConnected()
{
	return bIsConnected;
}
void PT_UV_TcpSession::getLocalAddr(char* ip, int ipLen, int& port)
{
	sockaddr_storage peername;
	int namelen = sizeof(peername);
	int r = uv_tcp_getsockname(m_tcpHandle, (struct sockaddr*)&peername, &namelen);
	r = uv_ip4_name((sockaddr_in*)&peername, ip, ipLen);
	port = ((sockaddr_in*)&peername)->sin_port;
}
void PT_UV_TcpSession::getRemoteAddr(char* ip, int ipLen, int& port)
{
	sockaddr_storage peername;
	int namelen = sizeof(peername);
	int r = uv_tcp_getpeername(m_tcpHandle, (struct sockaddr*)&peername, &namelen);
	r = uv_ip4_name((sockaddr_in*)&peername, ip, ipLen);
	port = ((sockaddr_in*)&peername)->sin_port;
}
//////////////////////////////////////////////////////////////////////////
// 接口
PT_TCP_Session::PT_TCP_SessionCallBack* PT_UV_TcpSession::GetCallBack()
{
	return getCallBack();
}
bool PT_UV_TcpSession::Connect(char* ip, int port, int timeout)
{
	return connect(ip, port, timeout);
}
void PT_UV_TcpSession::Shutdown()
{
	shutdown();
}
bool PT_UV_TcpSession::Send(char* buf, size_t len, void* data)
{
	return send(buf, len, data);
}
int PT_UV_TcpSession::StartTimer(int timeout, int repeat, void* data)
{
	return startTimer(timeout, repeat, data);
}
void PT_UV_TcpSession::StopTimer(int timerId)
{
	stopTimer(timerId);
}
bool PT_UV_TcpSession::IsConnected()
{
	return isConnected();
}
void PT_UV_TcpSession::GetLocalAddr(char* ip, int ipLen, int& port)
{
	getLocalAddr(ip, ipLen, port);
}
void PT_UV_TcpSession::GetRemoteAddr(char* ip, int ipLen, int& port)
{
	getRemoteAddr(ip, ipLen, port);
}
//////////////////////////////////////////////////////////////////////////
// 静态函数
//////////////////////////////////////////////////////////////////////////
// tcp 相关回调
void PT_UV_TcpSession::on_connection(uv_connect_t* handle, int status)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)(handle->data);

	if(!status)
	{
		//注册读取事件
		uv_read_start((uv_stream_t*)session->m_tcpHandle,
					  PT_UV_TcpSession::on_alloc,
					  PT_UV_TcpSession::on_read);
		session->bIsConnected = true;
		RecvMsg* msg = RecvMsg::GetConnectMsg();
		session->emitRecv(msg);
	}
	else
	{
		session->sendError(status);
		session->closeSendHandle();
	}

	session->bIsCheckingConnected = false;
	free(handle);
}
void PT_UV_TcpSession::on_connectTimeout(uv_timer_t* handle)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;

	if(!session->bIsConnected)
	{
		session->closeSendHandle();
		session->bIsCheckingConnected = false;
	}

	uv_timer_stop(handle);
	uv_close((uv_handle_t*)handle, PT_UV_TcpSession::on_close_handle);
}
void PT_UV_TcpSession::on_shutdown(uv_shutdown_t* req, int status)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)req->data;

	if(status)
	{
		session->sendError(status);
	}

	session->closeSendHandle();
	free(req);
}
void PT_UV_TcpSession::on_write(uv_write_t* req, int status)
{
	if(req->data)
	{
		WriteInfo* info = (WriteInfo*)req->data;
		info->status = status;
		info->req = NULL;

		std::list<WriteInfo*>::iterator iter = info->session->m_writingList.begin();

		for(; iter != info->session->m_writingList.end();)
		{
			if(*iter == info)
			{
				info->session->m_writingList.erase(iter++);
			}
			else
			{
				iter++;
			}
		}

		RecvMsg* msg = RecvMsg::GetWriteMsg(info);
		info->session->emitRecv(msg);

		if(status)
		{
			info->session->sendError(status);
			info->session->closeSendHandle();
		}
	}
	else
	{
		int x = 0;
	}

	free(req);
}
void PT_UV_TcpSession::on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
}
void PT_UV_TcpSession::on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;

	if(nread < 0)   //断开
	{
		session->sendError(nread);
		session->closeSendHandle();
	}
	else if(nread > 0)   //收到数据
	{
		uv_buf_t* data = (uv_buf_t*)malloc(sizeof(uv_buf_t));
		data->base = (char*)malloc(nread);
		data->len = nread;
		memcpy(data->base, buf->base, nread);

		RecvMsg* msg = RecvMsg::GetReadMsg(data);
		session->emitRecv(msg);
	}

	free(buf->base);
}
//////////////////////////////////////////////////////////////////////////
// 发送
void PT_UV_TcpSession::onSend(uv_async_t* handle)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;
	std::list<SendInfo*> dataList;
	SendInfo* buf = NULL;
	int i = 0;

	while(session->q_send.try_dequeue(buf))
	{
		dataList.push_back(buf);
	}

	if(!dataList.empty())
	{
		WriteInfo* info = (WriteInfo*)malloc(sizeof(WriteInfo));
		info->req = NULL;
		info->status = 0;
		info->session = (PT_UV_TcpSession*)handle->data;
		info->bufNum = dataList.size();
		info->buf = (uv_buf_t*)malloc(sizeof(uv_buf_t) * dataList.size());
		info->data = (void**)malloc(sizeof(void*) * dataList.size());

		std::list<SendInfo*>::iterator iter = dataList.begin();
		int i = 0;

		for(; iter != dataList.end();)
		{
			memcpy(info->buf + i, &(*iter)->buf, sizeof(uv_buf_t));
			info->data[i] = (*iter)->data;
			i++;
			free(*iter);
			dataList.erase(iter++);
		}

		uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
		req->data = info;
		info->req = req;
		info->session->m_writingList.push_back(info);
		uv_write(req, (uv_stream_t *)info->session->m_tcpHandle, info->buf, info->bufNum, PT_UV_TcpSession::on_write);
	}
}
//////////////////////////////////////////////////////////////////////////
// 回调线程通知回调
void PT_UV_TcpSession::OnConnectMsg()
{
	m_callBack->OnConnect();
}
void PT_UV_TcpSession::OnCloseMsg()
{
	m_callBack->OnClose();
	closeRecvHandle();
}
void PT_UV_TcpSession::OnReadMsg(uv_buf_t* buf)
{
	m_callBack->OnRecv(buf->base, buf->len);
	free(buf->base);
}
void PT_UV_TcpSession::OnWriteMsg(WriteInfo* info)
{
	for(int i = 0; i < info->bufNum; i++)
	{
		m_callBack->OnSend(info->data[i], info->status);
		free((info->buf + i)->base);
	}

	free(info->buf);
	free(info->data);
}
void PT_UV_TcpSession::OnErrMsg(int err)
{
	m_callBack->OnErr(err);
}
void PT_UV_TcpSession::OnTimerMsg(TimerInfo* info)
{
	m_callBack->OnTimer(info->data);
}
void PT_UV_TcpSession::OnStopTimerMsg(TimerInfo* info)
{
	m_callBack->OnStopTimer(info->data);
	free(info);
}
void PT_UV_TcpSession::handleRecvMsg(RecvMsg* msg)
{
	switch(msg->nType)
	{
		case RecvMsg::MsgType_onConnect:
			OnConnectMsg();
			break;

		case RecvMsg::MsgType_onRead:
			OnReadMsg((uv_buf_t*)msg->data);
			free(msg->data);
			msg->data = NULL;
			break;

		case RecvMsg::MsgType_onWrite:
			OnWriteMsg((WriteInfo*)msg->data);
			free(msg->data);
			msg->data = NULL;
			break;

		case RecvMsg::MsgType_onErr:
			OnErrMsg(msg->nInt);
			break;

		case RecvMsg::MsgType_onTimer:
			OnTimerMsg((TimerInfo*)msg->data);
			break;

		case RecvMsg::MsgType_onStopTimer:
			OnStopTimerMsg((TimerInfo*)msg->data);
			break;
	}
}
void PT_UV_TcpSession::onRecvMsg(uv_async_t* handle)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;
	RecvMsg* msg = NULL;
	bool isClosed = false;

	while(true)
	{
		if(session->q_recv.try_dequeue(msg))
		{
			if(msg->nType == RecvMsg::MsgType_onClose)
			{
				isClosed = true;
			}
			else
			{
				session->handleRecvMsg(msg);
			}

			free(msg);
			msg = NULL;
		}
		else
		{
			break;
		}
	};

	if(isClosed)
	{
		session->OnCloseMsg();
	}
}
//////////////////////////////////////////////////////////////////////////
// timer 线程回调
void PT_UV_TcpSession::onStartTimer(uv_async_t* handle)
{
	TimerInfo* info = (TimerInfo*)handle->data;

	if(info->session->bIsConnected)
	{
		info->session->m_timerList.push_back(info);
		uv_timer_init(info->session->t_tcp->loop(), info->timer);
		uv_timer_start(info->timer, PT_UV_TcpSession::onTimer, info->timeout, info->repeat);
	}
	else
	{
		free(info->timer);
		free(info);
	}

	uv_close((uv_handle_t*)handle, PT_UV_TcpSession::on_close_handle);
}
void PT_UV_TcpSession::onCloseTimer(uv_async_t* handle)
{
	StopTimerInfo* info = (StopTimerInfo*)handle->data;

	TimerInfo* timerinfo = NULL;
	std::list<TimerInfo*>::iterator iter = info->session->m_timerList.begin();

	for(; iter != info->session->m_timerList.end();)
	{
		if((*iter)->id == info->id)
		{
			timerinfo = *iter;
			info->session->m_timerList.erase(iter++);
			break;
		}
		else
		{
			iter++;
		}
	}

	if(timerinfo)
	{
		uv_timer_stop(timerinfo->timer);
		uv_close((uv_handle_t*)timerinfo->timer, PT_UV_TcpSession::on_close_handle);
		timerinfo->timer = NULL;
		RecvMsg* msg = RecvMsg::GetStopTimerMsg(timerinfo);
		timerinfo->session->emitRecv(msg);
	}

	free(info);
	uv_close((uv_handle_t*)handle, PT_UV_TcpSession::on_close_handle);
}

void PT_UV_TcpSession::onTimer(uv_timer_t* handle)
{
	TimerInfo* info = (TimerInfo*)handle->data;
	RecvMsg* timerMsg = RecvMsg::GetTimerMsg(info);
	info->session->emitRecv(timerMsg);

	if(!info->repeat)
	{
		std::list<TimerInfo*>::iterator iter = info->session->m_timerList.begin();

		for(; iter != info->session->m_timerList.end();)
		{
			if((*iter)->id == info->id)
			{
				info->session->m_timerList.erase(iter++);
				break;
			}
			else
			{
				iter++;
			}
		}

		uv_timer_stop(info->timer);
		uv_close((uv_handle_t*)info->timer, PT_UV_TcpSession::on_close_handle);
		info->timer = NULL;
		RecvMsg* stopMsg = RecvMsg::GetStopTimerMsg(info);
		info->session->emitRecv(stopMsg);
	}
}

//////////////////////////////////////////////////////////////////////////
// 关闭handle
void PT_UV_TcpSession::closeSendHandle()
{
	if(bIsConnected)
	{
		bIsConnected = false;
		clearWritingList();
		closeAllTimer();

		if(s_send)
		{
			uv_close((uv_handle_t*)s_send, PT_UV_TcpSession::on_closeSendHandle);
		}
	}
}
void PT_UV_TcpSession::closeTcpHandle()
{
	if(m_tcpHandle)
	{
		uv_close((uv_handle_t*)m_tcpHandle, PT_UV_TcpSession::on_closeTcpHandle);
	}
}
void PT_UV_TcpSession::closeRecvHandle()
{
	if(s_recv)
	{
		uv_close((uv_handle_t*)s_recv, PT_UV_TcpSession::on_closeRecvHandle);
	}
}
void PT_UV_TcpSession::closeAllTimer()
{
	TimerInfo* info = NULL;
	std::list<TimerInfo*>::iterator iter = m_timerList.begin();

	for(; iter != m_timerList.end();)
	{
		info = *iter;
		uv_timer_stop(info->timer);
		uv_close((uv_handle_t*)info->timer, PT_UV_TcpSession::on_close_handle);
		info->timer = NULL;
		RecvMsg* msg = RecvMsg::GetStopTimerMsg(info);
		emitRecv(msg);
		m_timerList.erase(iter++);
	}
}
void PT_UV_TcpSession::clearWritingList()
{
	WriteInfo* info = NULL;
	std::list<WriteInfo*>::iterator iter = m_writingList.begin();

	for(; iter != m_writingList.end();)
	{
		info = *iter;
		info->status = Err_ConnReset;
		info->req->data = NULL;
		RecvMsg* msg = RecvMsg::GetWriteMsg(info);
		emitRecv(msg);
		m_writingList.erase(iter++);
	}
}
void PT_UV_TcpSession::on_closeSendHandle(uv_handle_t* handle)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;
	session->s_send = NULL;
	session->closeTcpHandle();
	free(handle);
}
void PT_UV_TcpSession::on_closeTcpHandle(uv_handle_t* handle)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;
	session->m_tcpHandle = NULL;
	RecvMsg* msg = RecvMsg::GetCloseMsg();
	session->emitRecv(msg);
	free(handle);
}
void PT_UV_TcpSession::on_closeRecvHandle(uv_handle_t* handle)
{
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;
	session->s_recv = NULL;

	if(session->m_server)
	{
		session->m_server->removeSession(session);
	}

	free(handle);
}
void PT_UV_TcpSession::on_close_handle(uv_handle_t* handle)
{
	free(handle);
}


