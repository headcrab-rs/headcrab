# Contributing to Headcrab

Welcome to Headcrab! This is a large project with a huge scope, and there are many things you can help us with.
Documentation, code understandability, and contributor guides are amongs our top priorities.

You can start by taking a look at the [list of open issues] on GitHub.
However, because the project is young, not everything might be reflected in the issues descriptions, documentation, or code,
and if you think something is missing, please let us know!

If you are interested in working on an open issue, please leave a comment and we will assign you to it.
This will help other contributors to see if this issue is already being worked on by someone else.

If you want to work on something new and it's not listed on our issue tracker, feel free to create a new issue!
We encourage you to do this before you put your time to work on larger issues. This way, we can make sure that no work will be duplicated.

[list of open issues]: https://github.com/headcrab-rs/headcrab/issues

## Mentoring

If you are new to debuggers, systems programming, or Rust, we are happy to provide guidance and help you start contributing.
One of the main goals of this project is to create a tool that can be used for education, and we value feedback and involvement
from people with diverse backgrounds. You can find a list of recommended resources in [our documentation](/Documentation/Resources.md).

We have a list of issues tagged as "[good first issue](https://github.com/headcrab-rs/headcrab/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)"
which can be a good start. If you think that an issue's description is not clear enough, we encourage you to ask questions in comments.
And remember, there is no such thing as a dumb question!

Lastly, we have a dedicated [#learning](https://headcrab.zulipchat.com/#narrow/stream/248039-learning) stream on our Zulip chat where you can ask
questions and find more educational resources.

## Coding Guidelines

Currently, Headcrab is intended to work with the current stable version of Rust, but some components might require using `nightly` in the future.

We follow common Rust conventions and use default `rustfmt` format settings. Before submitting a pull request, please format it locally by running the following command:

```
$ cargo fmt
```

You can read more about [rustfmt online](https://github.com/rust-lang/rustfmt).

## Funding

If you are interested in supporting the project financially, we have an [OpenCollective](https://opencollective.com/headcrab/) organisation.
