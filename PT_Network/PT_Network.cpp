// PT_Network.cpp : 定义 DLL 应用程序的导出函数。
//

#include "PT_Network.h"
#include "PT_UV_TcpServer.h"
#include "PT_UV_TcpSession.h"
#include "PT_UV_SP_Session.h"
#include "PT_UV_SSL_Session.h"
// #include "PT_APP_Session.h"
#include "RsaEncryptor.h"
#include "MBedRSA.h"
#ifndef USE_MBEDTLS
RsaEncryptor gEncryptor;
#else
//MBedRSA thread_local gMbedtlsRSA;
#endif

namespace PT_Network
{

	void initOpenSSL(const char* pemFile, const char* pemFilePwd)
	{
#ifndef USE_MBEDTLS
		gEncryptor.Init();
#endif // USE_MBEDTLS



		if(pemFilePwd == NULL || strlen(pemFilePwd) == 0)
		{
#ifndef USE_MBEDTLS
			gEncryptor.SetPublicKeyFromFile(pemFile);
#else

#endif
		}
		else
		{
#ifndef USE_MBEDTLS
			gEncryptor.SetPrivateKeyFromFile(pemFile, pemFilePwd);
#else

#endif

		}
	}

	//client
	PT_TCP_Session* PT_TCP_Session::CreatUVSession(PT_TCP_SessionCallBack* callback)
	{
		return new PT_UV_TcpSession(callback, NULL);
	}

	PT_TCP_Session* PT_TCP_Session::CreatUVSessionSharedThread(PT_TCP_SessionCallBack* callback)
	{
		return new PT_UV_TcpSession(callback, PT_UV_TcpSession::g_recv);
	}

	PT_TCP_Session* PT_TCP_Session::CreatUVSPSession(PT_TCP_SessionCallBack* callback)
	{
		return new PT_UV_SP_Session(callback, NULL);
	}

	PT_TCP_Session* PT_TCP_Session::CreatUVSPSessionSharedThread(PT_TCP_SessionCallBack* callback)
	{
		return new PT_UV_SP_Session(callback, PT_UV_TcpSession::g_recv);
	}

	PT_Network::PT_TCP_Session* PT_TCP_Session::CreatUVSSLSession(PT_TCP_SessionCallBack* callback, bool isServer)
	{
		return new PT_UV_SSL_Session(callback, NULL, isServer);
	}

	PT_Network::PT_TCP_Session* PT_TCP_Session::CreatUVSSLSessionSharedThread(PT_TCP_SessionCallBack* callback, bool isServer)
	{
		return new PT_UV_SSL_Session(callback, PT_UV_TcpSession::g_recv, isServer);

	}

	void PT_TCP_Session::RemoveUVSession(PT_TCP_Session* session)
	{
		if(session)
		{
			delete session;
		}
	}


	//server
	PT_TCP_Server* PT_TCP_Server::CreatUVServer(PT_TCP_ServerCallBack* callback)
	{
		return new PT_UV_TcpServer(callback);
	}

	PT_TCP_Server* PT_TCP_Server::CreatUVServerWithThreadPool(PT_TCP_ServerCallBack* callback, int threadNum)
	{
		return new PT_UV_TcpServer(callback, threadNum);
	}

	void PT_TCP_Server::RemoveUVServer(PT_TCP_Server* server)
	{
		if(server)
		{
			delete(PT_TCP_Server*)server;
		}
	}

//
//  //APPclient
//  PT_APP_Session* PT_APP_Session::CreateAppSession(PT_APP_SessionCallBack* callback, bool bSSL, int nReconnNum, bool bServer)
//  {
//      return new PT_UV_APP_Session(callback, bSSL, nReconnNum, bServer);
//  }
//  PT_APP_Session* PT_APP_Session::CreateAppSession(PT_APP_SessionCallBack* callback, bool bSSL, int nReconnNum)
//  {
//      return new PT_UV_APP_Session(callback, bSSL, nReconnNum, false);
//  }
}