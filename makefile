INC      := -I./include/ -I/usr/local/include/
LIB_PATH := -L/usr/local/lib/ -luv -lboost_system -lpthread
LIBS     := $(LIB_PATH)
CC       := g++ -std=c++11
LD       := g++
CFLAGS   := -shared -fPIC -Wall $(INC)
SRC_PATH := ./PT_Network/
SOURCE   := $(SRC_PATH)PT_Network.cpp\
			$(SRC_PATH)PT_UV_SPSession.cpp\
			$(SRC_PATH)PT_UV_TcpServer.cpp\
			$(SRC_PATH)PT_UV_TcpSession.cpp\
			$(SRC_PATH)PT_UV_Thread.cpp

TARGET   := libPTNetwork.so
OBJS     := PT_Network.o PT_UV_SPSession.o PT_UV_TcpServer.o PT_UV_TcpSession.o PT_UV_Thread.o
$(TARGET): $(OBJS)
	$(LD) -shared -fPIC -o $(TARGET) $(OBJS) $(LIBS)
PT_Network.o : $(SRC_PATH)PT_Network.cpp
	$(CC) $(CFLAGS) -c $(SRC_PATH)PT_Network.cpp -o $@
PT_UV_SPSession.o : $(SRC_PATH)PT_UV_SPSession.cpp
	$(CC) $(CFLAGS) -c $(SRC_PATH)PT_UV_SPSession.cpp -o $@
PT_UV_TcpServer.o : $(SRC_PATH)PT_UV_TcpServer.cpp
	$(CC) $(CFLAGS) -c $(SRC_PATH)PT_UV_TcpServer.cpp -o $@
PT_UV_TcpSession.o : $(SRC_PATH)PT_UV_TcpSession.cpp
	$(CC) $(CFLAGS) -c $(SRC_PATH)PT_UV_TcpSession.cpp -o $@
PT_UV_Thread.o : $(SRC_PATH)PT_UV_Thread.cpp
	$(CC) $(CFLAGS) -c $(SRC_PATH)PT_UV_Thread.cpp -o $@
.PHONY: clean
install:
	cp $(TARGET) /usr/local/lib
	cp $(TARGET) /lib
clean:
	-rm -f $(OBJS)
cleanT:
	-rm -f $(TARGET)
