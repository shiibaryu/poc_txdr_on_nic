CC = gcc
INCLUDE := -I../libtlp/include 
LDFLAGS := -L../libtlp/lib
LDLIBS 	:=  -ltlp -lpthread
CFLAGS  := -g -Wall $(INCLUDE)

PROGNAME = nettlp_mnic_device 

all: $(PROGNAME)

.c.o:
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
