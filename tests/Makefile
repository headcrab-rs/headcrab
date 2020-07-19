CC       = gcc
CC_FLAGS =
SRCS = $(wildcard *.c)
BINS = $(patsubst %.c,%,$(SRCS))

.PHONY: all
all: $(BINS)

%: %.c
	$(CC) -g -no-pie -o $@ $^

clean:
	rm -f $(BINS)
