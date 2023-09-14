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
