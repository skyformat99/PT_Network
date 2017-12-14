#include "PT_UV_Thread.h"

//////////////////////////////////////////////////////////////////////////
// 线程
//////////////////////////////////////////////////////////////////////////

PT_UV_Thread::PT_UV_Thread() {
	m_loop = (uv_loop_t*)malloc(sizeof(uv_loop_t));
	uv_loop_init(m_loop);
	m_loop->data = this;
	bIsRuning = false;
}
PT_UV_Thread::~PT_UV_Thread(){
	free(m_loop);
}
//////////////////////////////////////////////////////////////////////////
void PT_UV_Thread::exec() {
	bIsRuning = true;
	int r = uv_run(m_loop, UV_RUN_DEFAULT);
	printf("thread %p exec over: %d\n", this, r);
	bIsRuning = false;
}
//////////////////////////////////////////////////////////////////////////
void PT_UV_Thread::run(){
	if (!bIsRuning) {
		uv_thread_create(&m_tid, PT_UV_Thread::threadEntry, this);
	}
}
void PT_UV_Thread::join() {
	uv_thread_join(&m_tid);
}
void PT_UV_Thread::cleanNeedCloseHandle() {
	uv_async_t* handle = (uv_async_t*)malloc(sizeof(uv_async_t));
	uv_async_init(m_loop, handle, PT_UV_Thread::on_clean);
	uv_async_send(handle);
}
int PT_UV_Thread::isSameThread(uv_thread_t &t) {
	return uv_thread_equal(&m_tid, &t);
}

uv_loop_t* PT_UV_Thread::loop(){
	return m_loop;
}
bool PT_UV_Thread::isRuning(){
	return bIsRuning;
}
//////////////////////////////////////////////////////////////////////////
// 静态方法
void PT_UV_Thread::threadEntry(void* arg) {
	((PT_UV_Thread*)arg)->exec();
}
void PT_UV_Thread::on_clean(uv_async_t* handle) {
//	printf("PT_UV_Thread on_clean\n");
	uv_close((uv_handle_t*)handle, PT_UV_Thread::on_close_handle);
}
void PT_UV_Thread::on_close_handle(uv_handle_t* handle) {
//	printf("PT_UV_Thread on_close_handle\n");
	free(handle);
}
//////////////////////////////////////////////////////////////////////////
// 线程池
//////////////////////////////////////////////////////////////////////////

PT_UV_ThreadPool::PT_UV_ThreadPool(int num)
{
	nThreadNuml = (num>0)?num:1;
	m_pool = new PT_UV_Thread[num];
}

PT_UV_ThreadPool::~PT_UV_ThreadPool()
{
}

void PT_UV_ThreadPool::run() {
	for (int i =0; i< nThreadNuml; ++i)
	{
		(m_pool + i)->run();
	}
}

PT_UV_Thread* PT_UV_ThreadPool::getThread() {
	PT_UV_Thread* thread = m_pool;
	for (int i = 1; i < nThreadNuml; ++i)
	{
		if (*thread > *(m_pool+i))
		{
			thread = m_pool + i;
		}
	}
	return thread;
}