CXXFLAGS += -g -Wall -Wextra -pthread

srcs = $(wildcard *.cpp)
#objs = li_server.o x3parser.o log.o udpx3cachequeue.o mediapcaploader.o x3statistics.o
objs = $(srcs:.cpp=.o)
libs = -lpthread -lpcap

all: li_server
.PHONY: all

li_server: $(objs)
	$(CXX) $(CXXFLAGS) $(libs) $^ -o $@

li_server.o: li_server.cpp log.h x3parser.h udpx3cachequeue.h li_server.h
	$(CXX) $(CXXFLAGS) -c $< 
# The line above equals $(CXX) $(CXXFLAGS) -c li_server.cpp

x3parser.o: x3parser.cpp x3parser.h log.h mediapcaploader.h x3statistics.h
	$(CXX) $(CXXFLAGS) -c $<

udpx3cachequeue.o: udpx3cachequeue.cpp udpx3cachequeue.h log.h 
	$(CXX) $(CXXFLAGS) -c $<

mediapcaploader.o: mediapcaploader.cpp mediapcaploader.h log.h
	$(CXX) $(CXXFLAGS) -c $<

x3statistics.o: x3statistics.cpp x3statistics.h log.h
	$(CXX) $(CXXFLAGS) -c $<

log.o: log.cpp log.h
	$(CXX) $(CXXFLAGS) -c $<


.PHONY: clean
clean:
	$(RM) -f $(objs) li_server *.gch
