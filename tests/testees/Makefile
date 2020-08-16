CC       = rustc
CC_FLAGS = -g -Copt-level=2 -Cforce-frame-pointers=yes
AS       = as
AS_FLAGS =
LD       = gcc
LD_FLAGS =
SRCS = $(wildcard *.rs) $(wildcard *.S)
BINS = $(patsubst %.S,%,$(patsubst %.rs,%,$(SRCS)))

.PHONY: all
all: $(BINS)

%: %.rs
	$(CC) $(CC_FLAGS) -o $@ $^

%: %.S
	$(AS) $(AS_FLAGS) -o $@.o $^
	$(LD) $(LD_FLAGS) -o $@ $@.o
	rm $@.o

clean:
	rm -f $(BINS)
