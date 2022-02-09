all:
	g++ --static -o hook64 -Wall -O3 -std=c++11 hook64.cc syscall_handler.cc -pthread
