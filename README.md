# Lang (TODO: choose a name)

A self-hosted, unsafe, compiled programming language.

## Features

- Functions
  - Support for importing external functions
- Variables
- Control flow
  - if-else
  - Short-circuiting and/or
  - while loops
  - for loops
  - Scope-based defer
- A simple type system
  - 64-bit integers
  - Booleans
  - Tuples
- C-style string literals
- Character literals

## Anti-features

- No macros
- No global variables

## Dependencies

- make
- LLVM

## Build instructions

```sh
make
```

## Contributing

Run `./update-bootstrap` before committing to ensure that the latest build of
the compiler (featuring your new changes) will be used to bootstrap the next
commit.
