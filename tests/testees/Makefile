CC       = rustc
CC_FLAGS = -g -C relocation-model=dynamic-no-pic
SRCS = $(wildcard *.rs)
BINS = $(patsubst %.rs,%,$(SRCS))

.PHONY: all
all: $(BINS)

%: %.rs
	$(CC) $(CC_FLAGS) -o $@ $^

clean:
	rm -f $(BINS)
