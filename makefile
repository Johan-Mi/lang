CFLAGS := -Wall -Wextra -Wpedantic $(shell llvm-config --cflags)
LDLIBS := $(shell llvm-config --ldflags --libs)

all: compiler
.PHONY: all

compiler: compiler.bc
	clang -o $@ $< $(LDLIBS)

compiler.bc: compiler.lang bootstrap
	./bootstrap $< $@

compile_flags.txt: makefile
	$(file >$@)
	$(foreach O,$(CFLAGS),$(file >>$@,$O))
