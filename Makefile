CXXFLAGS += -Wall -Wextra -pthread -Wno-unused-parameter
ifndef RELEASE
    CXXFLAGS += -g -O0
endif
srcs = $(wildcard *.cpp)
#objs = li_server.o x3parser.o log.o udpx3cachequeue.o mediapcaploader.o x3statistics.o
objs = $(srcs:.cpp=.o)
deps = $(srcs:.cpp=.dep)
libs = -lpthread -lpcap
ver_headfile = version.h
ver := $(shell echo "generate version.h";sed -e "s/<version>/$$(git describe)/g" < version.h.in > version.h.tmp;\
	if diff -q version.h.tmp version.h >/dev/null 2>&1; \
	then \
	    rm -f version.h.tmp; \
	else \
	    echo "version.h.in => version.h"; \
	    mv version.h.tmp version.h; \
	fi)

.PHONY: all clean 
all: li_server

-include $(deps)

li_server: $(objs)
	@echo "Linking $@"
	$(CXX) $(CXXFLAGS) $(filter-out version.h, $^) $(libs) -o $@
ifdef RELEASE
	strip --strip-unneeded -R .note -R .comment $@
endif

#version.h:
#	@echo "generate version.h"
#	@sed -e "s/<version>/$$(git describe)/g" \
#		< version.h.in > version.h.tmp
#	@if diff -q version.h.tmp version.h >/dev/null 2>&1; \
#	then \
#	    rm -f version.h.tmp; \
#	else \
#	    echo "version.h.in => version.h"; \
#	    mv version.h.tmp version.h; \
#	fi
#
%.o: %.cpp
	@echo "Compiling $@"
	$(CXX) $(CXXFLAGS) -c $<

%.dep: %.cpp
	@echo "Making dependency $@..."
	@set -e;$(RM) $@; \
	$(CXX) -MM -E $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	$(RM) $@.$$$$


#li_server.o: li_server.cpp log.h x3parser.h udpx3cachequeue.h li_server.h
#	$(CXX) $(CXXFLAGS) -c $< 
## The line above equals $(CXX) $(CXXFLAGS) -c li_server.cpp
#
#x3parser.o: x3parser.cpp x3parser.h log.h mediapcaploader.h x3statistics.h
#	$(CXX) $(CXXFLAGS) -c $<
#
#udpx3cachequeue.o: udpx3cachequeue.cpp udpx3cachequeue.h log.h 
#	$(CXX) $(CXXFLAGS) -c $<
#
#mediapcaploader.o: mediapcaploader.cpp mediapcaploader.h log.h
#	$(CXX) $(CXXFLAGS) -c $<
#
#x3statistics.o: x3statistics.cpp x3statistics.h log.h
#	$(CXX) $(CXXFLAGS) -c $<
#
#log.o: log.cpp log.h
#	$(CXX) $(CXXFLAGS) -c $<


clean:
	$(RM)  $(objs) li_server *.gch *.dep* $(ver_headfile)
