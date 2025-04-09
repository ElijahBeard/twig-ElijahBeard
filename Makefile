CXX=g++
CC=g++
CPPFLAGS=-Wall -O2

TARGET=twig
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