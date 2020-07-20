# Recommended reading

## Books

- "[GDB Internals](https://sourceware.org/gdb/wiki/Internals)" (also available in [PDF](https://www.sourceware.org/gdb/5/onlinedocs/gdbint.pdf)), Gilmore, J., Shebs S.

  This document describes internals of the GNU debugger, with details about key algorithms and the overall architecture.

- "[The Linux Programming Interface](https://man7.org/tlpi/)", Kerrisk, M. (2010), ISBN 978-1-59327-220-3

  The encyclopedia of Linux APIs. This is the best resource on using features provided by Linux to the fullest.

- "[UNIX Internals: The New Frontiers](https://openlibrary.org/books/OL792642M/UNIX_internals)", Vahalia, U. (1996), ISBN 9780131019089

  While this book is slightly dated, and not strictly related to the topic of debuggers, it's an excellent introduction to *nix and operating systems internals.
  Chapters on processes, signals, and virtual memory are still very much relevant today.

- "[How Debuggers Work: Algorithms, Data Structures, and Architecture](https://openlibrary.org/books/OL972343M/How_Debuggers_work)", Rosenberg, J.B. (1996), ISBN 9780471149668

  Despite the old age, many fundamental principles and algorithms described in this book remain applicable to this day.
  One major omission is that [DWARF](http://dwarfstd.org/), the standard debug info representation, is not covered.
  Sections about legacy platforms like OS/2, DOS, and 16-bit Windows can be skipped entirely.

- "[Modular Debugger, mdb](https://illumos.org/books/mdb/concepts-1.html#concepts-1)" (also available in [PDF](https://illumos.org/books/mdb/mdb-print.pdf)), 

  This book describes the illumos Modular Debugger (MDB), which is a general purpose debugging tool for the illumos operating system.
  It has many interesting features such as extensibility and [modular architecture](https://illumos.org/books/mdb/api-5.html#api-5).

## Blogs and articles

- "[Debugging Support in the Rust compiler](https://rustc-dev-guide.rust-lang.org/debugging-support-in-rustc.html)", an article from the Rust compiler dev guide describing the current state of debugging support in the Rust compiler.

- "[Writing a Linux Debugger](https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)", a series of blog posts by Sy Brand.

- "[How Debuggers Work](https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1)", a series of blog posts by Eli Bendersky.

- "[Your Debugger Sucks](https://robert.ocallahan.org/2019/11/your-debugger-sucks.html)", a blog post about the current debugging experience and how it should be improved.

## Specifications

- [DWARF Debugging Format Standard](http://dwarfstd.org/Download.php). DWARF is the standard most of the compilers & debuggers use (including Rust).

- [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/specification). A specification for a standard that provides interoperability between debuggers and code editors/IDEs.
