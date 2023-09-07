CFLAGS := -Wall -Wextra -Wpedantic $(shell llvm-config --cflags)
LDLIBS := $(shell llvm-config --ldflags --libs)

all: main
.PHONY: all

compile_flags.txt: makefile
	$(file >$@)
	$(foreach O,$(CFLAGS),$(file >>$@,$O))
