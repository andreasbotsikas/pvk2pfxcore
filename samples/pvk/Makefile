
# Editable options
TOP=$(HOME)/openssl
SSLINC=/usr/local/ssl/include
SSLLIB=/usr/local/ssl/lib

CFLAGS=-Wall -I$(SSLINC)

all: pvk

OBJS=pvkread.o pvkwrite.o pvkerr.o

$(OBJS): pvk.h

pvk: $(OBJS) pvk.o pvk.h
	$(CC) $(CFLAGS) -o pvk pvk.o $(OBJS) -L$(SSLLIB) -lcrypto

errors:
	perl $(TOP)/util/mkerr.pl -nostatic -conf pvk.ec -write *.c

clean:
	rm -f *.o pvk

