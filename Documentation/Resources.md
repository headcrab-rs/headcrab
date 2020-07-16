# Recommended reading

## Books

- "[The Linux Programming Interface](https://man7.org/tlpi/)", Kerrisk, M. (2010), ISBN 978-1-59327-220-3

  The encyclopedia of Linux APIs. This is the best resource on using features provided by Linux to the fullest.

- "[UNIX Internals: The New Frontiers](https://openlibrary.org/books/OL792642M/UNIX_internals)", Vahalia, U. (1996), ISBN 9780131019089

  While this book is slightly dated, and not strictly related to the topic of debuggers, it's an excellent introduction to *nix and operating systems internals.
  Chapters on processes, signals, and virtual memory are still very much relevant today.

- "[How Debuggers Work: Algorithms, Data Structures, and Architecture](https://openlibrary.org/books/OL972343M/How_Debuggers_work)", Rosenberg, J.B. (1996), ISBN 9780471149668

  Despite the old age, many fundamental principles and algorithms described in this book remain applicable to this day.
  One major omission is that [DWARF](http://dwarfstd.org/), the standard debug info representation, is not covered.
  Sections about legacy platforms like OS/2, DOS, and 16-bit Windows can be skipped entirely.

## Blogs and articles

- "[Writing a Linux Debugger](https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)", a series of blog posts by Sy Brand.

- "[How Debuggers Work](https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1)", a series of blog posts by Eli Bendersky.
