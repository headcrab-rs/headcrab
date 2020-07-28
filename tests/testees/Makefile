CC       = rustc
CC_FLAGS = -g -Copt-level=2
SRCS = $(wildcard *.rs)
BINS = $(patsubst %.rs,%,$(SRCS))

.PHONY: all
all: $(BINS)

%: %.rs
	$(CC) $(CC_FLAGS) -o $@ $^

clean:
	rm -f $(BINS)
