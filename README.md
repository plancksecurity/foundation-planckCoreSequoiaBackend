This library provides an implementation of the [p≡p Engine]'s
[cryptotech] interface using [Sequoia].

  [p≡p Engine]: https://gitea.pep.foundation/pEp.foundation/pEpEngine
  [cryptotech]: https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/cryptotech.h
  [Sequoia]: https://sequoia-pgp.org

Building
========

You need at least version 1.60 of `rustc` and `cargo`.

You can build this library as follows:

```
$ git clone https://gitea.pep.foundation/pEp.foundation/pEpEngineSequoiaBackend.git
$ cd pEpEngineSequoiaBackend
$ mkdir -p /tmp/pep_engine_sequoia_backend
$ CARGO_TARGET_DIR=/tmp/pep_engine_sequoia_backend cargo build # Add --release for a release build
$ CARGO_TARGET_DIR=/tmp/pep_engine_sequoia_backend cargo test
```

This will generate, among others
`/tmp/pep_engine_sequoia_backend/debug/pep_engine_sequoia_backend.pc`.
This can be used to easily link to the library *in place*.  That is,
no installation is required.

Hence to build and test the engine, we can do:

```
$ cd ~/src/pEpEngine
$ export PKG_CONFIG_PATH=/tmp/pep_engine_sequoia_backend/debug${PKG_CONFIG_PATH+:$PKG_CONFIG_PATH}
$ make
$ LD_LIBRARY_PATH=$(for p in $(pkg-config pep_engine_sequoia_backend --libs-only-L); do echo ${p#-L}; done | paste -sd ':')${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH} RUST_BACKTRACE=1 make -C test test
```

Of course when installing the engine, we'll need to distribute the
generated library.

Note: when profiling the library (or doing a release), be sure to
build in release mode!  That is, build the library with `cargo build
--release` and replace `debug` with `release` in the second set of
commands.

When built in debug mode, the library always generates trace output.
If you encounter problems in release mode, you can get a trace of the
library's execution by setting the `PEP_TRACE` environment
variable. For example:

```
$ cd ~/src/pEpEngine/test
$ PKG_CONFIG_PATH=/tmp/pep_engine_sequoia_backend/debug${PKG_CONFIG_PATH+:$PKG_CONFIG_PATH} LD_LIBRARY_PATH=$(for p in $(pkg-config pep_engine_sequoia_backend --libs-only-L); do echo ${p#-L}; done | paste -sd ':')${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH} PEP_TRACE=1 ./EngineTests -- --gtest_filter=DeleteKeyTest.check_delete_single_pubkey
```
