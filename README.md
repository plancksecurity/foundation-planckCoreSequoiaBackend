This library provides an implementation of the [pEp Engine]'s
[cryptotech] interface using [Sequoia].

  [pEp Engine]: https://gitea.pep.foundation/pEp.foundation/pEpEngine
  [cryptotech]: https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/cryptotech.h
  [Sequoia]: https://sequoia-pgp.org

# Building

## Linux and MacOS

You need at least version 1.63 of `rustc` and `cargo`.

You can build this library as follows:

```
$ git clone https://gitea.pep.foundation/pEp.foundation/pEpEngineSequoiaBackend.git
$ cd pEpEngineSequoiaBackend
$ make
$ make install
```

To configure how this library is built, edit `local.conf`.

When built in debug mode, the library always generates trace output.
If you encounter problems in release mode, you can get a trace of the
library's execution by setting the `PEP_TRACE` environment
variable.

## Windows

On Windows, the Sequoia PGP backend for the pEp engine also uses the
Botan backend.

### Use the Visual Studio compatible Rust compiler

You can check this by trying:

```text
C:\Users\vb\source\repos\pEpEngineSequoiaBackend> rustup show active-toolchain
1.60.0-x86_64-pc-windows-msvc (default)
```

### Call NMake with the delivered NMakefile

```text
C:\Users\vb\source\repos\pEpEngineSequoiaBackend> nmake /F NMakefile

Microsoft (R) Program Maintenance Utility, Version 14.34.31937.0
Copyright (C) Microsoft Corporation. Alle Rechte vorbehalten.

        cargo build --features crypto-cng --no-default-features --release
    Finished release [optimized] target(s) in 0.20s

Built target\release\pep_engine_sequoia_backend.dll
```

### To get a debug version instead of the release set environment DEBUG=debug

```text
C:\Users\vb\source\repos\pEpEngineSequoiaBackend> nmake /F NMakefile /E DEBUG=debug

Microsoft (R) Program Maintenance Utility, Version 14.34.31937.0
Copyright (C) Microsoft Corporation. Alle Rechte vorbehalten.

        cargo build --features crypto-cng --no-default-features
    Finished dev [unoptimized + debuginfo] target(s) in 0.18s

Built target\debug\pep_engine_sequoia_backend.dll
```

Unlike with GNU Make, `DEBUG` must not be defined if you want to build a
release.
