# Headcrab

[![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://headcrab.zulipchat.com) [![Build Status](https://travis-ci.org/headcrab-rs/headcrab.svg?branch=master)](https://travis-ci.org/headcrab-rs/headcrab) [![Build Status](https://api.cirrus-ci.com/github/headcrab-rs/headcrab.svg?task=stable%20x86_64-unknown-freebsd-12)](https://cirrus-ci.com/github/headcrab-rs/headcrab)

[**Contributing**](CONTRIBUTING.md) | [**Documentation**](Documentation) | [**Chat**](https://headcrab.zulipchat.com)

A modern Rust debugging library.

## Goals

This project's goal is to provide a modern debugger library for Rust so that you could build custom debuggers specific for your application. It will be developed with modern operating systems and platforms in mind.

You can learn more about the goals and reasoning behind the project in the following blog posts:

* [The Soul of a New Debugger](https://nbaksalyar.github.io/2020/07/12/soul-of-a-new-debugger.html)
* [A Future for Rust Debugging](http://nbaksalyar.github.io/2020/05/19/rust-debug.html)

## Roadmap

List of phase 1 goals for the project:

- Modular API and extensibility.
- Read & modify memory of other processes and control their execution (cross-platform: x86_64 for Linux & macOS).
- Basic symbolication for Rust (read DWARF debug information and translate symbols into addresses).
- Get information about process threads.
- Read & write variables in the thread-local storage.
- Setting breakpoints at given locations.

Long-term goals:

- Rust expression parser (reusing MIR and other components from the Rust compiler).
- Read complex data structures.
- Make symbolication reusable for eBPF and dynamic tracing.
- JSON-RPC and support for [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/).
- Command-line interface.
- Integrate with rr for reverse debugging.
- Collaborative debugging.
- Use the [LLVM DExTer](https://github.com/llvm/llvm-project/tree/master/debuginfo-tests/dexter) to improve user experience.
- Support more platforms and operating systems (Illumos, FreeBSD, OpenBSD, Windows).

## Contributing

Please refer to the "[Contributing to Headcrab](CONTRIBUTING.md)" document for more information about how you can help the project.
You can also join the community chat at https://headcrab.zulipchat.com

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
