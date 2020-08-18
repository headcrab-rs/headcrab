# Headcrab

[![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://headcrab.zulipchat.com) [![Build Status](https://travis-ci.org/headcrab-rs/headcrab.svg?branch=master)](https://travis-ci.org/headcrab-rs/headcrab) [![Build Status](https://api.cirrus-ci.com/github/headcrab-rs/headcrab.svg?task=stable%20x86_64-unknown-freebsd-12)](https://cirrus-ci.com/github/headcrab-rs/headcrab) ![windows](https://github.com/headcrab-rs/headcrab/workflows/windows/badge.svg?branch=master) [![Financial Contributors on Open Collective](https://opencollective.com/headcrab/all/badge.svg?label=financial+contributors)](https://opencollective.com/headcrab)

[**Contributing**](CONTRIBUTING.md) | [**Documentation**](Documentation) | [**Chat**](https://headcrab.zulipchat.com) | [**Website**](https://headcrab.rs)

A modern Rust debugging library.

## Goals

This project's goal is to provide a modern debugger library for Rust so that you could build custom debuggers specific for your application. It will be developed with modern operating systems and platforms in mind.

- [List of Phase 1 goals](https://github.com/headcrab-rs/headcrab/blob/master/Documentation/Design.md#phase-1)
- [List of Phase 1 open issues](https://github.com/headcrab-rs/headcrab/milestone/1)

## Using Headcrab

Currently, Headcrab supports Linux x86_64 as the primary target.
It's intended to be used as a library, but at this time it's not production-ready and the API stability is not guaranteed.

You can try some example applications. E.g., a command line interface to some of the exposed functions:

```
cargo run --example repl
```

## Contributing

This project exists thanks to all the people who contribute.

Please refer to the "[Contributing to Headcrab](CONTRIBUTING.md)" document for more information about how you can help the project.
You can also join the community chat at https://headcrab.zulipchat.com

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/headcrab/contribute)]

#### Individuals

<a href="https://opencollective.com/headcrab"><img src="https://opencollective.com/headcrab/individuals.svg?width=890"></a>

#### Sponsors

Support this project with your organization. Your logo will show up here with a link to your website. [[Become a sponsor](https://opencollective.com/headcrab/contribute)]

<a href="https://opencollective.com/headcrab/sponsor/0/website"><img src="https://opencollective.com/headcrab/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/1/website"><img src="https://opencollective.com/headcrab/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/2/website"><img src="https://opencollective.com/headcrab/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/3/website"><img src="https://opencollective.com/headcrab/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/4/website"><img src="https://opencollective.com/headcrab/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/5/website"><img src="https://opencollective.com/headcrab/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/6/website"><img src="https://opencollective.com/headcrab/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/7/website"><img src="https://opencollective.com/headcrab/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/8/website"><img src="https://opencollective.com/headcrab/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/headcrab/sponsor/9/website"><img src="https://opencollective.com/headcrab/sponsor/9/avatar.svg"></a>

## Long-term goals

- Rust expression parser (reusing MIR and other components from the Rust compiler).
- Read complex data structures.
- Make symbolication reusable for eBPF and dynamic tracing.
- JSON-RPC and support for [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/).
- Command-line interface.
- Integrate with rr for reverse debugging.
- Collaborative debugging.
- Use the [LLVM DExTer](https://github.com/llvm/llvm-project/tree/master/debuginfo-tests/dexter) to improve user experience.
- Support more platforms and operating systems (Illumos, FreeBSD, OpenBSD, Windows).

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
