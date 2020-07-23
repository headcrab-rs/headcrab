# High-level Design & Plan

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

The project is split into several loosely coupled major components:

- **Target**. This is the component that interacts with the operating system. It provides an abstract uniform interface for operations such as memory reading & writing, breakpoints (both internal and user-level), step-in, step-over, and step-out operations, hardware registers, backtraces, threads, and so forth. Targets are supposed to be pluggable components and one platform can support multiple targets (e.g., we can have a native target, a GDB serial protocol, and the core dump target supported for Linux).

- **Symbolication**. This component translates human-readable symbols into addresses recognised by the machine and the other way around. There could be multiple symbol sources: they can be read from the DWARF debug information, supplied by the compiler, or read from some other source. Currently, we only aim for providing Rust symbolication component.

- **Integration/API**. At this level, we can combine multiple techniques provided by the target & symbolication layers to achieve some interesting effects on the higher level. For example, an expression parser would belong here: it can parse symbols from an expression, find their addresses using the symbolication API, and read the actual values using the target API. This is also where we provide a JSON-RPC API to integrate with other tools such as code editors or IDEs.

- **Command line/UI**. A general-purpose user interface is out of scope of the Headcrab project (which is a debugger library or framework as opposed to a universal debugger tool). The UI can be provided by an existing code editor or IDE, or it can be implemented as part of another project that would interface with Headcrab's API.

Please keep in mind that the current state of the code base does not always reflect the design outlined here. If you find that something is missing and it's not listed on our issue tracker, please let us know!

### Target

Concrete targets should implement traits defined as part of the Target API. They are conditionally-compiled, and can be flexibly configured: for example, if you're building a debugger tool only to work with core dumps, you should be able to build Headcrab only with this target enabled. By default, all targets that a given platform supports should be enabled.

The feature set that we intend to cover (please keep in mind that the API is loosely defined and is prone to change):

- `Target::read(&self) -> ReadMemory` - returns a trait implementation (`ReadMemory`, see below) that can be used to read memory from a debuggee process. The trait can be implemented using different strategies: e.g., on Linux we can use `process_vm_read(2)` in the majority of cases, but `ptrace(2)` might be required to cover some edge cases (e.g., when a memory page is read-protected). The concrete memory reading strategy (or a combination of them) should be chosen by the implementor, and a user should not be aware of it.

    - `ReadMemory::read<T>(mut self, val: &mut T, remote_address: usize)` - reads a value `T` from the debuggee process at the given remote address. This function can be called multiple times: it builds a sequence of operations that can be executed with a single call. For non-primitive types, [`std::mem::MaybeUninit`](https://doc.rust-lang.org/stable/std/mem/union.MaybeUninit.html) can be used to safely work with uninitialized values. The lifetime of `ReadMemory` should not exceed the lifetime of `&mut T` references it contains.

    - `ReadMemory::apply(self) -> Vec<Result<(), ReadError>>` - executes the read operation and returns a list of addresses where the read operation has failed (the address can be contained within the `ReadError` type). This function is not required to be atomic and values can be read partially.

- `Target::write(&mut self) -> WriteMemory` - returns a trait implementation (`WriteMemory`, see below) that can be used to write memory to a debuggee process. The implementation should account for the possibility of page write protections. For example, on Linux `ptrace(2)` can be used to rewrite even protected memory pages, albeit inefficiently, and a concrete strategy should be chosen on a case-by-case basis without a user's knowledge.

    - `WriteMemory::write<T>(mut self, val: &mut T, remote_address: usize)` - writes a value `T` to the debuggee process at the given remote address. This function can be called multiple times: it builds a sequence of operations that can be executed with a single call. Type `T` should be initialised and the lifetime of `WriteMemory` should not exceed the lifetime of `&mut T` references it contains.

    - `WriteMemory::apply(mut self) -> Vec<Result<(), WriteError>>` - executes the write operation and returns a list of addresses where the write operation has failed (the address can be contained within the `WriteError` type). This operation is not required to be atomic and values can be written partially.

- `Target::next_event(&self) -> Option<DebugEvent>` - blocks & waits for a next debug event (such as `DebugEvent::BreakpointHit`) to occur.

- `Target::breakpoints(&mut self) -> &mut BreakpointsRef` - provides a view into a set of target breakpoints. It can be used to set, disable, and remove breakpoints. Internally, the `BreakpointsRef` struct can use `WriteMemory` to write the corresponding interrupt instructions, and this implementation can be shared across many target implementations.

    - `enum Breakpoint { Regular(usize), Conditional { addr: usize, cond: Box<fn(&mut Target) -> bool> } }` - the function in the conditional breakpoint will be executed each time the breakpoint is hit. It should return a boolean indicating whether a condition is met or not.

    - `BreakpointsRef::set(&mut self, bps: &[Breakpoint]) -> Result<(), Vec<BreakpointError>>` - sets a list of breakpoints at the provided addresses. In the case of error, returns a list of breakpoints that weren't set along with the error descriptions.

    - `BreakpointsRef::get_all(&self) -> &[Breakpoint]` - returns a list of all set breakpoints.

    - `BreakpointsRef::find_by_addr(&self, remote_addr: usize) -> &[Breakpoint]` - returns a list of all set breakpoints at the given address.

    - `BreakpointsRef::disable(&mut self, remote_addrs: &[usize]) -> Result<(), Vec<BreakpointError>>` - temporarily disable all breakpoints at the given addresses.

    - `BreakpointsRef::enable(&mut self, remote_addrs: &[usize]) -> Result<(), Vec<BreakpointError>>` - re-enable a previously disabled breakpoints at the giveen addresses.

    - `BreakpointsRef::remove(&mut self, remote_addrs: &[usize]) -> Result<(), Vec<BreakpointError>>` - remove all breakpoints at the given addresses.

### Symbolication

_This section will be expanded in the future._
