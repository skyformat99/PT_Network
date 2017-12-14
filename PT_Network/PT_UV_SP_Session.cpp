#include "PT_UV_SP_Session.h"

PT_UV_SP_Session::PT_UV_SP_Session(PT_TCP_SessionCallBack* callback, PT_UV_Thread* recvThread)
	: PT_UV_TcpSession(this, recvThread)
{
	m_cb = callback;

	szRecvBuffer = malloc(DEF_PT_MSG_RECVBUFF_SIZE);
	szSendBuffer = malloc(DEF_PT_MSG_BUFF_SIZE);
	nBuffSize = 0;
	memset(szRecvBuffer, 0, DEF_PT_MSG_RECVBUFF_SIZE);
	memset(szSendBuffer, 0, DEF_PT_MSG_BUFF_SIZE);
}


PT_UV_SP_Session::~PT_UV_SP_Session()
{
	free(szRecvBuffer);
	szRecvBuffer = NULL;
	free(szSendBuffer);
	szSendBuffer = NULL;
}

//////////////////////////////////////////////////////////////////////////
// 回调
void PT_UV_SP_Session::OnConnect()
{
	if(m_cb)
	{
		m_cb->OnConnect();
	}
}
void PT_UV_SP_Session::OnClose()
{
	if(m_cb)
	{
		m_cb->OnClose();
	}
}
void PT_UV_SP_Session::OnSend(void* data, int err)
{
	if (m_cb)
	{
		m_cb->OnSend(data, err);
	}
}
void PT_UV_SP_Session::OnRecv(char* buf, size_t len)
{
	//实现拼包
	if(nBuffSize + len > DEF_PT_MSG_RECVBUFF_SIZE)
	{
		nBuffSize = 0;
		if (m_cb)
		{
			m_cb->OnErr(Err_RecvBufOverFlow);
		}
	//	std::cout << "缓存区溢出！" << std::endl;
	}

	memcpy((char*)szRecvBuffer + nBuffSize, buf, len);
	nBuffSize += len;

	while(1)
	{
		if(nBuffSize < sizeof(PT_Msg_Header))
		{
			return;          // 数据长度不够
		}

		int size = ((PT_Msg_Header*)szRecvBuffer)->nLen + sizeof(PT_Msg_Header);

		if(nBuffSize >= size)
		{
			if(m_cb)
			{
				m_cb->OnRecv((char*)szRecvBuffer + sizeof(PT_Msg_Header), ((PT_Msg_Header*)szRecvBuffer)->nLen);
			}

			nBuffSize -= size;
			memcpy(szRecvBuffer, (char*)szRecvBuffer + size, nBuffSize);
		}
		else
		{
			return;
		}
	}
}

void PT_UV_SP_Session::OnErr(int err)
{
	if(m_cb)
	{
		m_cb->OnErr(err);
	}
};

void PT_UV_SP_Session::OnTimer(void* data)
{
	if(m_cb)
	{
		m_cb->OnTimer(data);
	}
}
void PT_UV_SP_Session::OnStopTimer(void* data)
{
	if(m_cb)
	{
		m_cb->OnStopTimer(data);
	}
}
//////////////////////////////////////////////////////////////////////////
// 重写父类接口
PT_TCP_Session::PT_TCP_SessionCallBack* PT_UV_SP_Session::GetCallBack()
{
	return m_cb;
}
bool PT_UV_SP_Session::Connect(char* ip, int port)
{
	return connect(ip, port, 0);
}
void PT_UV_SP_Session::Shutdown()
{
	shutdown();
}
bool PT_UV_SP_Session::Send(char* buf, size_t len, void* data)
{
	((PT_Msg_Header*)szSendBuffer)->nLen = len;
	memcpy((char*)szSendBuffer + sizeof(PT_Msg_Header), buf, len);
	return send((char*)szSendBuffer, len + sizeof(PT_Msg_Header), data);
}
int PT_UV_SP_Session::StartTimer(int timeout, int repeat, void* data)
{
	return startTimer(timeout, repeat, data);
}
void PT_UV_SP_Session::StopTimer(int timerId)
{
	stopTimer(timerId);
}

bool PT_UV_SP_Session::IsConnected()
{
	return isConnected();
}
void PT_UV_SP_Session::GetLocalAddr(char* ip, int ipLen, int& port)
{
	return getLocalAddr(ip, ipLen, port);
}
void PT_UV_SP_Session::GetRemoteAddr(char* ip, int ipLen, int& port)
{
	getRemoteAddr(ip, ipLen, port);
}
