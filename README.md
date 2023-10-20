# Lang (TODO: choose a name)

A self-hosted, unsafe, compiled programming language.

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
