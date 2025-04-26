CXX=g++
CC=g++
CPPFLAGS=-Wall -std=c++11 -g -O2

TARGET=shrub
SRCS=${wildcard *.cc}
OBJECTS=${SRCS:.cc=.o}
HEADERS=${wildcard *.h}

all: $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJECTS): $(HEADERS)

clean:
	rm -f $(TARGET) *.o
	rm -f ../Twig_tools/172.31.128.0_24.dmp
	rm -f ../Twig_tools/shrub