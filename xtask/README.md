
To run code coverage locally, do the following:

Do this once during setup:
```
rustup component add llvm-tools-preview
cargo install grcov
```

Subsequently, run:
```
cargo xtask coverage --dev
```