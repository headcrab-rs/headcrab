# Headcrab Linux Target Implementation Details

## Reading & writing memory

We use [`process_vm_readv(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html) and
[`process_vm_writev(2)`](https://man7.org/linux/man-pages/man2/process_vm_writev.2.html) system calls to work with debuggee's memory.
These system calls were added in Linux 3.2 and allow to read & write debuggee's memory at multiple locations with a single context switch,
which is important for the debugger's peformance.
