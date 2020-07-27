.globl main
main:
    # Breakpoint trap on Linux
    # FIXME use right interrupt on macOS
    int $3
    nop
    int $3
    mov $0, %rax
    ret
