#ifndef PT_TCP_THREAD_H
#define PT_TCP_THREAD_H

#include <uv.h>
#include <atomic>

class PT_UV_Thread {
public:
	PT_UV_Thread ();
	virtual ~PT_UV_Thread ();

private:
	uv_loop_t* m_loop;						//事件循环
	uv_thread_t m_tid;                      //线程
	std::atomic<bool> bIsRuning;
private:
	void exec();
public:
	void run();
	void join();
	void cleanNeedCloseHandle();
	int isSameThread(uv_thread_t &t);

	uv_loop_t* loop();
	bool isRuning();

	bool operator > (const PT_UV_Thread& d) {
		return m_loop->active_handles > d.m_loop->active_handles;
	};
	bool operator < (const PT_UV_Thread& d) {
		return m_loop->active_handles < d.m_loop->active_handles;
	};
private:
	static void threadEntry(void* arg);
	static void on_clean(uv_async_t* handle);
	static void on_close_handle(uv_handle_t* handle);
};

class PT_UV_ThreadPool
{
public:
	PT_UV_ThreadPool(int num);
	virtual ~PT_UV_ThreadPool();

private:
	int nThreadNuml;
	PT_UV_Thread* m_pool;

public:
	void run();
	PT_UV_Thread* getThread();

};

#endif