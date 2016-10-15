
all: li_server
.PHONY: all

li_server: li_server.o x3parser.o log.o udpx3cachequeue.o rtpmixer.o
	g++ -o li_server li_server.o x3parser.o log.o udpx3cachequeue.o rtpmixer.o -Wall -lpcap -lpthread -g

li_server.o: li_server.h log.h x3parser.h udpx3cachequeue.h li_server.cpp
	g++ -c li_server.h log.h x3parser.h udpx3cachequeue.h li_server.cpp -g

x3parser.o: x3parser.h log.h x3parser.cpp
	g++ -c  x3parser.h log.h x3parser.cpp -g

udpx3cachequeue.o: udpx3cachequeue.h log.h udpx3cachequeue.cpp
	g++ -c  udpx3cachequeue.h log.h udpx3cachequeue.cpp -g

rtpmixer.o: rtpmixer.h log.h  rtpmixer.cpp
	g++ -c  rtpmixer.h log.h rtpmixer.cpp -g

log.o: log.h log.cpp
	g++ -c  log.h log.cpp -g


.PHONY: clean
clean:
	rm -f *.o li_server
