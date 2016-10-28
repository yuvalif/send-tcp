CC?=gcc
CFLAGS?=-O2
LDFLAGS?=

TARGET=send-tcp

SOURCES=send-tcp.c
OBJECTS=$(SOURCES:.c=.o)
LIBS = -lpcap

.PHONY: all clean

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

-include $(OBJECTS:.o=.d)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	$(CC) -MM $(CFLAGS) $< > $*.d

clean:
	$(RM) *.o *.d $(TARGET)

