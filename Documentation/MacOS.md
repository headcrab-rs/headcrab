# Running Headcrab on macOS

macOS has additional security measures and doesn't allow to manipulate other processes unless you have permissions
to do so.

Add linker options to `.cargo/config`:

    [build]
    rustflags = ["-C", "link-args=-sectcreate __TEXT __info_plist Info.plist"]

You can check if the section has been added to the binary by running

    $ codesign -dvvv <path to binary> 2>&1 | grep Info.plist

## Address space layout randomization

ASLR can be disabled with an undocumented attribute for `posix_spawn`: `_POSIX_SPAWN_DISABLE_ASLR` (0x0100)
