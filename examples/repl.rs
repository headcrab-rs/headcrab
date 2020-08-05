#[cfg(target_os = "linux")]
fn main() {
    example::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("This example is currently not supported for OSes other than Linux");
}

#[cfg(target_os = "linux")]
mod example {
    use headcrab::{
        symbol::{DisassemblySource, RelocatedDwarf},
        target::{AttachOptions, LinuxTarget, UnixTarget},
    };

    struct Context {
        remote: Option<LinuxTarget>,
        debuginfo: Option<RelocatedDwarf>,
        disassembler: DisassemblySource,
    }

    impl Context {
        fn remote(&self) -> Result<&LinuxTarget, Box<dyn std::error::Error>> {
            if let Some(remote) = &self.remote {
                Ok(remote)
            } else {
                Err("No running process".to_string().into())
            }
        }

        fn set_remote(&mut self, remote: LinuxTarget) {
            // FIXME kill/detach old remote
            self.remote = Some(remote);
            self.debuginfo = None;
        }

        fn load_debuginfo_if_necessary(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            if self.debuginfo.is_none() {
                let memory_maps = self.remote()?.memory_maps()?;
                self.debuginfo = Some(RelocatedDwarf::from_maps(&memory_maps)?);
            }
            Ok(())
        }

        fn debuginfo(&self) -> &RelocatedDwarf {
            self.debuginfo.as_ref().unwrap()
        }
    }

    pub fn main() {
        let mut rl = rustyline::Editor::<()>::with_config(
            rustyline::Config::builder().auto_add_history(true).build(),
        );
        let mut context = Context {
            remote: None,
            debuginfo: None,
            disassembler: DisassemblySource::new(),
        };

        let mut cmds = vec![];
        let mut exec_cmd = None;
        let mut args = std::env::args();
        let repl_name = args.next().unwrap();
        while let Some(arg) = args.next() {
            let err = match &*arg {
                "-ex" => {
                    if let Some(arg) = args.next() {
                        cmds.push(arg);
                        continue;
                    } else {
                        "Found flag -ex without argument".to_string()
                    }
                }
                _ if arg.starts_with("-") => {
                    format!("Found argument '{}' which wasn't expected", arg)
                }
                _ => {
                    if args.next().is_none() {
                        exec_cmd = Some(arg);
                        break;
                    } else {
                        "Debuggee arguments are not yet supported".to_string()
                    }
                }
            };
            println!(
                "error: {}

    USAGE:
        {} [OPTIONS] executable-file

    OPTIONS:
        -ex <COMMAND>           Run command on startup",
                err, repl_name
            );
            std::process::exit(1);
        }

        if let Some(exec_cmd) = exec_cmd {
            println!("Starting program: {}", exec_cmd);
            context.set_remote(match LinuxTarget::launch(&exec_cmd) {
                Ok((target, status)) => {
                    println!("{:?}", status);
                    target
                }
                Err(err) => {
                    println!("\x1b[91mError while launching debuggee: {}\x1b[0m", err);
                    std::process::exit(1);
                }
            });
        }

        for command in cmds.into_iter() {
            println!("\x1b[96m> {}\x1b[0m", command);
            match run_command(&mut context, &command) {
                Ok(()) => {}
                Err(err) => {
                    println!("\x1b[91mError: {}\x1b[0m", err);
                }
            }
        }

        loop {
            match rl.readline("(headcrab) ") {
                Ok(command) => {
                    if command == "q" || command == "quit" || command == "exit" {
                        println!("Exit");
                        return;
                    }
                    match run_command(&mut context, &command) {
                        Ok(()) => {}
                        Err(err) => {
                            println!("\x1b[91mError: {}\x1b[0m", err);
                        }
                    }
                }
                Err(rustyline::error::ReadlineError::Eof)
                | Err(rustyline::error::ReadlineError::Interrupted) => {
                    println!("Exit");
                    return;
                }
                Err(err) => {
                    println!("\x1b[91mError: {:?}\x1b[0m", err);
                    std::process::exit(1);
                }
            }
        }
    }

    fn run_command(context: &mut Context, command: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut parts = command.trim().split(' ').map(str::trim);
        match parts.next() {
            Some("exec") => {
                if let Some(cmd) = parts.next() {
                    println!("Starting program: {}", cmd);
                    let (remote, status) = LinuxTarget::launch(cmd)?;
                    println!("{:?}", status);
                    context.set_remote(remote);
                }
            }
            Some("attach") => {
                if let Some(pid) = parts.next() {
                    let pid = nix::unistd::Pid::from_raw(pid.parse()?);
                    println!("Attaching to process {}", pid);
                    let (remote, status) = LinuxTarget::attach(
                        pid,
                        AttachOptions {
                            kill_on_exit: false,
                        },
                    )?;
                    println!("{:?}", status);
                    // FIXME detach or kill old remote
                    context.set_remote(remote);
                }
            }
            Some("detach") => {
                context.remote()?.detach()?;
                context.remote = None;
            }
            Some("kill") => println!("{:?}", context.remote()?.kill()?),
            Some("si") | Some("stepi") => println!("{:?}", context.remote()?.step()?),
            Some("cont") | Some("continue") => println!("{:?}", context.remote()?.unpause()?),
            Some("regs") => match parts.next() {
                Some("read") => println!("{:?}", context.remote()?.read_regs()?),
                Some(sub) => Err(format!("Unknown `regs` subcommand `{}`", sub))?,
                None => Err(format!(
                    "Expected subcommand found nothing. Try `regs read`"
                ))?,
            },
            Some("bt") | Some("backtrace") => {
                context.load_debuginfo_if_necessary()?;

                let regs = context.remote()?.read_regs()?;

                // Read stack
                let mut stack: [usize; 1024] = [0; 1024];
                unsafe {
                    context
                        .remote()?
                        .read()
                        .read(&mut stack, regs.rsp as usize)
                        .apply()?;
                }

                let call_stack: Vec<_> = match parts.next() {
                    Some("fp") | None => headcrab::symbol::unwind::frame_pointer_unwinder(
                        context.debuginfo(),
                        &stack[..],
                        regs.rip as usize,
                        regs.rsp as usize,
                        regs.rbp as usize,
                    )
                    .collect(),
                    Some("naive") => headcrab::symbol::unwind::naive_unwinder(
                        context.debuginfo(),
                        &stack[..],
                        regs.rip as usize,
                    )
                    .collect(),
                    Some(sub) => Err(format!("Unknown `bt` subcommand `{}`", sub))?,
                };
                for func in call_stack {
                    let res = context.debuginfo().with_addr_frames(
                        func,
                        |mut frames: addr2line::FrameIter<_>| {
                            let mut first_frame = true;
                            while let Some(frame) = frames.next()? {
                                let name = frame
                                    .function
                                    .map(|f| Ok(f.demangle()?.into_owned()))
                                    .transpose()
                                    .map_err(|err: gimli::Error| err)?
                                    .unwrap_or_else(|| "<unknown>".to_string());

                                let location = frame
                                    .location
                                    .map(|loc| {
                                        format!(
                                            "{}:{}",
                                            loc.file.unwrap_or("<unknown file>"),
                                            loc.line.unwrap_or(0),
                                        )
                                    })
                                    .unwrap_or_default();

                                if first_frame {
                                    println!("{:016x} {} {}", func, name, location);
                                } else {
                                    println!("                 {} {}", name, location);
                                }

                                first_frame = false;
                            }
                            Ok(first_frame)
                        },
                    )?;
                    match res {
                        Some(true) | None => {
                            println!(
                                "{:016x} at {}",
                                func,
                                context
                                    .debuginfo()
                                    .get_address_demangled_name(func)
                                    .as_deref()
                                    .unwrap_or("<unknown>")
                            );
                        }
                        Some(false) => {}
                    }
                }
            }
            Some("dis") | Some("disassemble") => {
                let ip = context.remote()?.read_regs()?.rip;
                let mut code = [0; 64];
                unsafe {
                    context
                        .remote()?
                        .read()
                        .read(&mut code, ip as usize)
                        .apply()?;
                }
                let disassembly = context.disassembler.source_snippet(&code, ip, true)?;
                println!("{}", disassembly);
            }

            // Patch the `pause` instruction inside a function called `breakpoint` to be a
            // breakpoint. This is useful while we don't have support for setting breakpoints at
            // runtime yet.
            // FIXME remove once real breakpoint support is added
            Some("_patch_breakpoint_function") => {
                context.load_debuginfo_if_necessary()?;
                // Test that `a_function` resolves to a function.
                let breakpoint_addr = context.debuginfo().get_symbol_address("breakpoint").unwrap() + 4 /* prologue */;
                // Write breakpoint to the `breakpoint` function.
                let mut pause_inst = 0 as libc::c_ulong;
                unsafe {
                    context
                        .remote()?
                        .read()
                        .read(&mut pause_inst, breakpoint_addr)
                        .apply()
                        .unwrap();
                }
                // pause (rep nop); ...
                assert_eq!(
                    &pause_inst.to_ne_bytes()[0..2],
                    &[0xf3, 0x90],
                    "Pause instruction not found"
                );
                let mut breakpoint_inst = pause_inst.to_ne_bytes();
                // int3; nop; ...
                breakpoint_inst[0] = 0xcc;
                nix::sys::ptrace::write(
                    context.remote()?.pid(),
                    breakpoint_addr as *mut _,
                    libc::c_ulong::from_ne_bytes(breakpoint_inst) as *mut _,
                )
                .unwrap();
            }
            Some("") | None => {}
            Some(command) => Err(format!("Unknown command `{}`", command))?,
        }

        Ok(())
    }
}
