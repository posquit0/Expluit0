CC = gcc
CFLAGS = -c -g -Wall
OFLAGS = -g -Wall

SRCDIR = .
OBJDIR = .
OUTDIR = .


OBJS = scode_runner.o scode_encoder.o

all : scode_runner scode_encoder

scode_runner : scode_runner.o
	$(CC) -o $(OUTDIR)/scode_runner $(OBJDIR)/scode_runner.o
	rm -f $(OBJDIR)/scode_runner.o

scode_encoder : scode_encoder.o
	$(CC) -o $(OUTDIR)/scode_encoder $(OBJDIR)/scode_encoder.o
	rm -f $(OBJDIR)/scode_encoder.o

scode_runner.o :
	$(CC) $(CFLAGS) $(SRCDIR)/scode_runner.c -o $(OBJDIR)/scode_runner.o

scode_encoder.o :
	$(CC) $(CFLAGS) $(SRCDIR)/scode_encoder.c -o $(OBJDIR)/scode_encoder.o

clean :
	rm -f $(OUTDIR)/*.out $(OUTDIR)/scode_runner $(OUTDIR)/scode_encoder $(OUTDIR)/$(OBJS)
