#ifndef _PT_UV_APP_SESSION_H_
#define _PT_UV_APP_SESSION_H_

#include "PT_Network.h"
#include <boost/date_time/posix_time/posix_time.hpp>  
using namespace PT_Network;

class PT_UV_APP_Session :
	public PT_APP_Session,
	public PT_TCP_Session::PT_TCP_SessionCallBack
{
public:
	PT_UV_APP_Session(PT_APP_Session::PT_APP_SessionCallBack* callback, bool bOpenSSL, int nReconnNum, bool bServer);
	virtual ~PT_UV_APP_Session();
public://回调
	void OnConnect();
	void OnClose();
	void OnSend(void* data, int err);
	void OnRecv(char* buf, size_t len);
	void OnErr(int err);
	void OnTimer(void* data);
	void OnStopTimer(void* data);
public:
	bool connect(char* ip, int port);
	void Shutdown();										///< 主动断开链接
	void Send(char* buff, size_t len, void* data);

	bool IsConnected();
	void GetLocalAddr(char* ip, int ipLen, int& port);
	void GetRemoteAddr(char* ip, int ipLen, int& port);
private:
	PT_APP_Session::PT_APP_SessionCallBack* m_cb;
	PT_TCP_Session* m_session;
	int             m_nReconnNum;
	bool            b_ifSSlL;

	boost::posix_time::ptime m_recvDataTime;

};

#endif//_PT_APP_SESSION_H_
