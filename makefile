CFLAGS := -Wall -Wextra -Wpedantic $(shell llvm-config --cflags)
LDLIBS := $(shell llvm-config --ldflags --libs)

all: stage2
.PHONY: all

test: compiler.bc stage2.bc
	diff $^
.PHONY: test

%: %.bc
	clang -o $@ $< $(LDLIBS)

stage2.bc: compiler.lang compiler
	./compiler $< $@

compiler.bc: compiler.lang bootstrap
	./bootstrap $< $@

compile_flags.txt: makefile
	$(file >$@)
	$(foreach O,$(CFLAGS),$(file >>$@,$O))
