# High-level Pesign & Plan

## Phase 1

Creating a new debugger is not an easy task and requires a lot of work to cover different target platforms and edge cases.

Luckily, we don't need all that to create a useful tool that can provide a lot of value to developers, and at this stage
we focus mainly on creating a framework for smaller tools that can solve specific tasks rather than on creating a full-fledged
debugger with command line, UI, IDE/editor integration and so forth.

This framework will be comprised of some fundamental building blocks which can be used to interactively probe another process
or a core dump file. This also does not necessarily mean that a debuggee process has to be stopped to observe its behaviour,
as some debug techniques work with running processes.

For the phase 1, we also limit our scope to 2 targets: macOS and Linux on x86_64. The purpose of having two targets rather than
just one is to make sure that any design choices that will be made during the development phase will account for the modular project
structure & the need to support multiple target platforms at later stages.

Phase 1 will be considered done when we will have these basics available to users in form of a library:

### Target layer

- Reading and writing memory of a debuggee process.
  - Primitive types (e.g.: i8, u64, double).
  - Collections (arrays, slices, `std::vec::Vec`).
  - Structures.
  - Enums.
- Getting and setting values of hardware registers.
- Obtaining backtraces.
- Setting breakpoints at specified addresses (step-in, step-out, and step-over are optional).
- Getting info about threads and reading/writing to the thread-local storage.

### Symbolication layer

- Reading DWARF debug info from binary executables:
  - Function addresses.
  - Variable addresses (including static and thread-local vars).
  - Structures & enums information.
- Support source maps (mapping memory addresses to source code).

## Phase 2 and next stages

Next stage goals for the project is to provide more complete debugging experience, more integrations, and more supported platforms.

- One of the main targets is a JSON-RPC API to communicate with the debugger core. This will allow us to start building UIs for the debugger
  in form of command-line, desktop, or web apps.

- We will also need to support the GDB Remote Serial Protocol as one of the targets to integrate with other debugger cores (such as
  [mozilla rr](https://rr-project.org/) for deterministic debugging).

- This is also a stage where we can begin experiments with the Rust compiler integration for an expression parser.

## Components and Design

_To be expanded_
