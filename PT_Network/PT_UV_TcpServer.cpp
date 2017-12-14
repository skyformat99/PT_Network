#include "PT_UV_TcpServer.h"


PT_UV_TcpServer::PT_UV_TcpServer(PT_TCP_ServerCallBack* callBack)
{
	init(callBack, 0);
}

PT_UV_TcpServer::PT_UV_TcpServer(PT_TCP_ServerCallBack* callBack, int threadNum) {
	init(callBack, threadNum);
}

PT_UV_TcpServer::~PT_UV_TcpServer()
{
}
//////////////////////////////////////////////////////////////////////////
void PT_UV_TcpServer::init(PT_TCP_ServerCallBack* callBack, int threadNum) {
	m_callBack = callBack;
	t_tcp = new PT_UV_Thread;
	m_tcpHandle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(t_tcp->loop(), m_tcpHandle);
	m_tcpHandle->data = this;
	t_pool = threadNum ? new PT_UV_ThreadPool(threadNum): NULL;
}

//////////////////////////////////////////////////////////////////////////
// 接口函数
PT_TCP_Server::PT_TCP_ServerCallBack* PT_UV_TcpServer::GetCallBack() {
	return m_callBack;
}
int PT_UV_TcpServer::Listen(char* ip, int port) {
	if (m_callBack)
	{
		sockaddr_in addr;
		uv_ip4_addr(ip, port, &addr);
		uv_tcp_bind(m_tcpHandle, (const struct sockaddr*)&addr, 0);
		int r = uv_listen((uv_stream_t*)m_tcpHandle, port, PT_UV_TcpServer::on_connection);
		if (r) {
			printf("Listen error %s\n", uv_strerror(r));
		}
		else {
			printf("Is Listening: %d\n", port);
		}
		if (!t_tcp->isRuning()) {
			t_tcp->run();
		}
		return r;
	} else {
		printf("There is no callBack obj, stop listen\n");
		return 1;
	}
}

void PT_UV_TcpServer::Stop() {
 	std::set<PT_UV_TcpSession*>::iterator iter = m_sessionSet.begin();
	for (;iter != m_sessionSet.end(); iter++)
	{
		(*iter)->Shutdown();
	}
	uv_close((uv_handle_t*)m_tcpHandle, PT_UV_TcpServer::on_close_handle);
	t_tcp->join();
	m_sessionSet.clear();
}
void PT_UV_TcpServer::removeSession(PT_UV_TcpSession* session) {
	uv_async_t* handle = (uv_async_t*)malloc(sizeof(uv_async_t));
	handle->data = session;
	uv_async_init(t_tcp->loop(), handle, PT_UV_TcpServer::on_removeSession);
	uv_async_send(handle);
}
//////////////////////////////////////////////////////////////////////////
// 静态函数
void PT_UV_TcpServer::on_connection(uv_stream_t* server, int status) {
//	printf("PT_TCP_Server on_connection status: %d \n", status);
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		return;
	} else {
		PT_UV_TcpSession* session = (PT_UV_TcpSession*)((PT_UV_TcpServer*)server->data)->m_callBack->OnAccept();

		PT_UV_ThreadPool* pool = ((PT_UV_TcpServer*)server->data)->t_pool;
		if (pool)
		{
			session->accpet(server, ((PT_UV_TcpServer*)server->data)->t_tcp, pool->getThread());
		}
		else {
			session->accpet(server, ((PT_UV_TcpServer*)server->data)->t_tcp, NULL);
		}
		((PT_UV_TcpServer*)server->data)->m_sessionSet.insert(session);
	}
}

void PT_UV_TcpServer::on_removeSession(uv_async_t* handle) {
	PT_UV_TcpSession* session = (PT_UV_TcpSession*)handle->data;
	PT_UV_TcpServer* server = session->getServer();
	std::set<PT_UV_TcpSession*>::iterator iter = session->getServer()->m_sessionSet.find(session);
	if (iter != session->getServer()->m_sessionSet.end())
	{
		session->getServer()->m_sessionSet.erase(iter);
	}
	server->m_callBack->OnRemove(session);
	uv_close((uv_handle_t*)handle, PT_UV_TcpServer::on_close_handle);
}
void PT_UV_TcpServer::on_close_handle(uv_handle_t* handle) {
//	printf("PT_UV_TcpServer on_close_handle \n");
	free(handle);
}