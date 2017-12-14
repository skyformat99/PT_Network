#include "stdafx.h"
#include "PT_APP_Session.h"


PT_UV_APP_Session::PT_UV_APP_Session(PT_APP_Session::PT_APP_SessionCallBack* callback, bool bOpenSSL, int nReconnNum, bool bServer)
{
	m_nReconnNum = nReconnNum;
	m_cb = callback;
	b_ifSSlL = bOpenSSL;
	if (bOpenSSL)
	{
		m_session = PT_TCP_Session::CreatUVSSLSessionSharedThread(this, bServer);
	}
	else
	{
		m_session = PT_TCP_Session::CreatUVSPSessionSharedThread(this);
	}
}

PT_UV_APP_Session::~PT_UV_APP_Session()
{
	if (m_session)
	{
		PT_TCP_Session::RemoveUVSession(m_session);
	}
}

void PT_UV_APP_Session::OnConnect()
{

	m_session->StartTimer(1000, 2000, NULL);

	if (m_cb)
	{
		m_cb->OnConnect();
	}
}
void PT_UV_APP_Session::OnClose()
{
	if (m_cb)
	{
		m_cb->OnClose();
	}
}
void PT_UV_APP_Session::OnSend(void* data, int err)
{
	if (m_cb)
	{
		m_cb->OnSend(data, err);
	}
}
void PT_UV_APP_Session::OnRecv(char* buf, size_t len)
{
	if (m_cb)
	{
		m_cb->OnRecv(buf, len);
	}
}
void PT_UV_APP_Session::OnErr(int err)
{
	if (m_cb)
	{
		m_cb->OnErr(err);
	}
}
void PT_UV_APP_Session::OnTimer(void* data)
{

}

void PT_UV_APP_Session::OnStopTimer(void* data)
{

}

bool PT_UV_APP_Session::connect(char* ip, int port)
{
	if (m_session)
	{
		return m_session->Connect(ip, port, 0);
	}
	return false;
}
void PT_UV_APP_Session::Shutdown()
{
	if (m_session)
	{
		m_session->Shutdown();
	}
}
void PT_UV_APP_Session::Send(char* buff, size_t len, void* data)
{
	if (m_session)
	{
		m_session->Send(buff, len, data);
	}
}

bool PT_UV_APP_Session::IsConnected()
{
	if (m_session)
	{
		return m_session->IsConnected();
	}
	return false;
}
void PT_UV_APP_Session::GetLocalAddr(char* ip, int ipLen, int& port)
{
	if (m_session)
	{
		m_session->GetLocalAddr(ip, ipLen, port);
	}
}
void PT_UV_APP_Session::GetRemoteAddr(char* ip, int ipLen, int& port) 
{
	if (m_session)
	{
		m_session->GetRemoteAddr(ip, ipLen, port);
	}
}