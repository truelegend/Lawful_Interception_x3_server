
all: li_server
.PHONY: all

li_server: li_server.o x3parser.o log.o udpx3cachequeue.o
	g++ -o li_server li_server.o x3parser.o log.o udpx3cachequeue.o -Wall -lpcap -lpthread

li_server.o: li_server.h log.h x3parser.h udpx3cachequeue.h

x3parser.o: x3parser.h log.h

udpx3cachequeue.o: udpx3cachequeue.h log.h

log.o: log.h


.PHONY: clean
clean:
	rm -f *.o li_server
