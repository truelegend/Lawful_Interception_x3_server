
all: li_server
.PHONY: all

li_server: li_server.o x3parser.o log.o
	g++ -o li_server li_server.o x3parser.o log.o -Wall -lpcap -lpthread

li_server.o: li_server.h log.h x3parser.h

x3parser.o: x3parser.h

log.o: log.h


.PHONY: clean
clean:
	rm -f *.o li_server
