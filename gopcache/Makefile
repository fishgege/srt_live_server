CC = gcc  
C++ = g++  
LINK = g++  

LIBS = -L/usr/local/lib -pthread -llog4cplus

#must add -fPIC option  
CCFLAGS = $(COMPILER_FLAGS) -c -g  -fPIC -Wall
C++FLAGS = $(COMPILER_FLAGS) -c -g -fPIC -Wall -std=c++11
  
TARGET=mpeg_ts_demux_test
  
INCLUDES = -I. -I../logging -I.. -I../include -I../include/srt

C++FILES = ./ts_gop_cache.cpp ./mpeg_ts_demux_test.cpp
CFILES = 

OBJFILE = $(CFILES:.c=.o) $(C++FILES:.cpp=.o)  

all:$(TARGET)  
  
$(TARGET): $(OBJFILE)  
	$(LINK) $^ -Wall $(LIBS) -o $@
 
%.o:%.c  
	$(CC) -o $@ $(CCFLAGS) $< $(INCLUDES)  
  
%.o:%.cpp  
	$(C++) -o $@ $(C++FLAGS) $< $(INCLUDES)  
  
  
clean:  
	rm -rf $(TARGET)  
	rm -rf $(OBJFILE)  


