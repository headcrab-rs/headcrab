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
    use std::{
        cell::Cell,
        path::{Path, PathBuf},
        rc::Rc,
    };

    use headcrab::{
        symbol::{DisassemblySource, RelocatedDwarf},
        target::{AttachOptions, LinuxTarget, UnixTarget},
    };

    use repl_tools::HighlightAndComplete;
    use rustyline::CompletionType;

    repl_tools::define_repl_cmds!(enum ReplCommand {
        /// Start a program to debug
        Exec: PathBuf,
        /// Attach to an existing program
        Attach: String,
        /// Detach from the debugged program. Leaving it running when headcrab exits
        Detach: (),
        /// Kill the program being debugged
        Kill: (),
        /// Step one instruction
        Stepi|si: (),
        /// Continue the program being debugged
        Continue|cont: (),
        // FIXME move the `read:` part before the `--` in the help
        /// read: List registers and their content for the current stack frame
        Registers|regs: String,
        /// Print backtrace of stack frames
        Backtrace|bt: String,
        /// Disassemble some a several instructions starting at the instruction pointer
        Disassemble|dis: (),
        /// Print all local variables of current stack frame
        Locals: (),
        /// Print this help
        Help|h: (),
        /// Exit
        Exit|quit|q: (),
    });

    type ReplHelper = repl_tools::MakeHelper<ReplCommand>;

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
        let color = Rc::new(Cell::new(true));

        let mut rl = rustyline::Editor::<ReplHelper>::with_config(
            rustyline::Config::builder()
                .auto_add_history(true)
                .completion_type(CompletionType::List)
                .build(),
        );
        rl.set_helper(Some(ReplHelper::new(color.clone())));

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
                "--no-color" => {
                    color.set(false);
                    continue;
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
        -ex <COMMAND>           Run command on startup
        --no-color              Disable colors",
                err, repl_name
            );
            std::process::exit(1);
        }

        if let Some(exec_cmd) = exec_cmd {
            println!("Starting program: {}", exec_cmd);
            context.set_remote(match LinuxTarget::launch(Path::new(&exec_cmd)) {
                Ok((target, status)) => {
                    println!("{:?}", status);
                    target
                }
                Err(err) => {
                    if color.get() {
                        println!("\x1b[91mError while launching debuggee: {}\x1b[0m", err);
                    } else {
                        println!("Error while launching debuggee: {}", err);
                    }
                    std::process::exit(1);
                }
            });
        }

        for command in cmds.into_iter() {
            if color.get() {
                println!("\x1b[96m> {}\x1b[0m", command);
            } else {
                println!("> {}", command);
            }
            match run_command(&mut context, &color, &command) {
                Ok(()) => {}
                Err(err) => {
                    if color.get() {
                        println!("\x1b[91mError: {}\x1b[0m", err);
                    } else {
                        println!("Error: {}", err);
                    }
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
                    match run_command(&mut context, &color, &command) {
                        Ok(()) => {}
                        Err(err) => {
                            if color.get() {
                                println!("\x1b[91mError: {}\x1b[0m", err);
                            } else {
                                println!("Error: {}", err);
                            }
                        }
                    }
                }
                Err(rustyline::error::ReadlineError::Eof)
                | Err(rustyline::error::ReadlineError::Interrupted) => {
                    println!("Exit");
                    return;
                }
                Err(err) => {
                    if color.get() {
                        println!("\x1b[91mError: {:?}\x1b[0m", err);
                    } else {
                        println!("Error: {:?}", err);
                    }
                    std::process::exit(1);
                }
            }
        }
    }

    fn run_command(
        context: &mut Context,
        color: &Cell<bool>,
        command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if command == "" {
            return Ok(());
        } else if command == "_patch_breakpoint_function" {
            // Patch the `pause` instruction inside a function called `breakpoint` to be a
            // breakpoint. This is useful while we don't have support for setting breakpoints at
            // runtime yet.
            // FIXME remove once real breakpoint support is added

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

            return Ok(());
        }

        let command = ReplCommand::from_str(command)?;
        match command {
            ReplCommand::Help(()) => {
                ReplCommand::print_help(std::io::stdout(), color.get()).unwrap();
            }
            ReplCommand::Exec(cmd) => {
                println!("Starting program: {}", cmd.display());
                let (remote, status) = LinuxTarget::launch(&cmd)?;
                println!("{:?}", status);
                context.set_remote(remote);
            }
            ReplCommand::Attach(pid) => {
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
            ReplCommand::Detach(()) => {
                context.remote()?.detach()?;
                context.remote = None;
            }
            ReplCommand::Kill(()) => println!("{:?}", context.remote()?.kill()?),
            ReplCommand::Stepi(()) => println!("{:?}", context.remote()?.step()?),
            ReplCommand::Continue(()) => println!("{:?}", context.remote()?.unpause()?),
            ReplCommand::Registers(sub_cmd) => match &*sub_cmd {
                "" => Err(format!(
                    "Expected subcommand found nothing. Try `regs read`"
                ))?,
                "read" => println!("{:?}", context.remote()?.read_regs()?),
                _ => Err(format!("Unknown `regs` subcommand `{}`", sub_cmd))?,
            },
            ReplCommand::Backtrace(sub_cmd) => {
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

                let call_stack: Vec<_> = match &*sub_cmd {
                    "" | "fp" => headcrab::symbol::unwind::frame_pointer_unwinder(
                        context.debuginfo(),
                        &stack[..],
                        regs.rip as usize,
                        regs.rsp as usize,
                        regs.rbp as usize,
                    )
                    .collect(),
                    "naive" => headcrab::symbol::unwind::naive_unwinder(
                        context.debuginfo(),
                        &stack[..],
                        regs.rip as usize,
                    )
                    .collect(),
                    _ => Err(format!("Unknown `bt` subcommand `{}`", sub_cmd))?,
                };
                for func in call_stack {
                    let res = context
                        .debuginfo()
                        .with_addr_frames(func, |_addr, mut frames| {
                            let mut first_frame = true;
                            while let Some(frame) = frames.next()? {
                                let name = frame
                                    .function
                                    .as_ref()
                                    .map(|f| Ok(f.demangle()?.into_owned()))
                                    .transpose()
                                    .map_err(|err: gimli::Error| err)?
                                    .unwrap_or_else(|| "<unknown>".to_string());

                                let location = frame
                                    .location
                                    .as_ref()
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
                        })?;
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
            ReplCommand::Disassemble(()) => {
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
            ReplCommand::Locals(()) => {
                let regs = context.remote()?.read_regs()?;
                let func = regs.rip as usize;
                let res = context.debuginfo().with_addr_frames(
                    func,
                    |func, mut frames: headcrab::symbol::FrameIter| {
                        let mut first_frame = true;
                        while let Some(frame) = frames.next()? {
                            let name = frame
                                .function
                                .as_ref()
                                .map(|f| Ok(f.demangle()?.into_owned()))
                                .transpose()
                                .map_err(|err: gimli::Error| err)?
                                .unwrap_or_else(|| "<unknown>".to_string());

                            let location = frame
                                .location
                                .as_ref()
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

                            let (_dwarf, unit, dw_die_offset) = frame
                                .function_debuginfo()
                                .ok_or_else(|| "No dwarf debuginfo for function".to_owned())?;

                            // FIXME handle DW_TAG_inlined_subroutine with DW_AT_frame_base in parent DW_TAG_subprogram
                            let frame_base = if let Some(frame_base) =
                                unit.entry(dw_die_offset)?.attr(gimli::DW_AT_frame_base)?
                            {
                                let frame_base = frame_base.exprloc_value().unwrap();
                                let res = headcrab::symbol::dwarf_utils::evaluate_expression(
                                    unit,
                                    frame_base,
                                    None,
                                    get_linux_x86_64_reg(regs),
                                )?;
                                assert_eq!(res.len(), 1);
                                assert_eq!(res[0].bit_offset, None);
                                assert_eq!(res[0].size_in_bits, None);
                                Some(match res[0].location {
                                    gimli::Location::Register {
                                        register: gimli::X86_64::RBP,
                                    } => regs.rbp,
                                    ref loc => unimplemented!("{:?}", loc), // FIXME
                                })
                            } else {
                                None
                            };

                            frame.each_argument::<Box<dyn std::error::Error>, _>(
                                func as u64,
                                |local| show_local("arg", context, unit, frame_base, regs, local),
                            )?;

                            frame.each_local::<Box<dyn std::error::Error>, _>(
                                func as u64,
                                |local| show_local("    ", context, unit, frame_base, regs, local),
                            )?;

                            frame.print_debuginfo();

                            first_frame = false;
                        }
                        Ok(first_frame)
                    },
                )?;
                match res {
                    Some(true) | None => {
                        println!("no locals");
                    }
                    Some(false) => {}
                }
            }
            ReplCommand::Exit(()) => unreachable!("Should be handled earlier"),
        }

        Ok(())
    }

    fn get_linux_x86_64_reg(
        regs: libc::user_regs_struct,
    ) -> impl Fn(gimli::Register, gimli::ValueType) -> gimli::Value {
        move |reg, ty| {
            let val = match reg {
                gimli::X86_64::RAX => regs.rax,
                gimli::X86_64::RBX => regs.rbx,
                gimli::X86_64::RCX => regs.rcx,
                gimli::X86_64::RDX => regs.rdx,
                gimli::X86_64::RSI => regs.rsi,
                gimli::X86_64::RDI => regs.rdi,
                gimli::X86_64::RSP => regs.rsp,
                gimli::X86_64::RBP => regs.rbp,
                gimli::X86_64::R9 => regs.r9,
                gimli::X86_64::R10 => regs.r10,
                gimli::X86_64::R11 => regs.r11,
                gimli::X86_64::R12 => regs.r12,
                gimli::X86_64::R13 => regs.r13,
                gimli::X86_64::R14 => regs.r14,
                gimli::X86_64::R15 => regs.r15,
                reg => unimplemented!("{:?}", reg), // FIXME
            };
            match ty {
                gimli::ValueType::Generic => gimli::Value::Generic(val),
                gimli::ValueType::U64 => gimli::Value::U64(val),
                _ => unimplemented!(),
            }
        }
    }

    fn show_local<'a>(
        kind: &str,
        context: &Context,
        unit: &gimli::Unit<headcrab::symbol::Reader<'a>>,
        frame_base: Option<u64>,
        regs: libc::user_regs_struct,
        local: headcrab::symbol::Local,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let type_size = if let Some(type_) = local.type_() {
            if let Some(size) = type_.attr(gimli::DW_AT_byte_size)? {
                size.udata_value().unwrap()
            } else if type_.tag() == gimli::DW_TAG_pointer_type {
                std::mem::size_of::<usize>() as u64 // FIXME use pointer size of remote
            } else {
                0
            }
        } else {
            0
        };

        let value = match local.value() {
            headcrab::symbol::LocalValue::Expr(expr) => {
                let res = headcrab::symbol::dwarf_utils::evaluate_expression(
                    unit,
                    expr.clone(),
                    frame_base,
                    get_linux_x86_64_reg(regs),
                )?;
                assert_eq!(res.len(), 1);
                assert_eq!(res[0].bit_offset, None);
                assert_eq!(res[0].size_in_bits, None);
                match res[0].location {
                    gimli::Location::Address { address } => match type_size {
                        8 => {
                            let mut val = 0u64;
                            unsafe {
                                context
                                    .remote()
                                    .unwrap()
                                    .read()
                                    .read(&mut val, address as usize)
                                    .apply()
                                    .unwrap();
                            }
                            format!("{}", val)
                        }
                        _ => unimplemented!("{}", type_size),
                    },
                    gimli::Location::Value { value } => match value {
                        gimli::Value::Generic(val) => format!("{}", val),
                        val => unimplemented!("{:?}", val),
                    },
                    ref loc => unimplemented!("{:?}", loc),
                }
            }
            headcrab::symbol::LocalValue::Const(val) => format!("const {}", val),
            headcrab::symbol::LocalValue::OptimizedOut => "<optimized out>".to_owned(),
            headcrab::symbol::LocalValue::Unknown => "<unknown>".to_owned(),
        };

        println!(
            "{} {} = {}",
            kind,
            local.name()?.unwrap_or("<no name>"),
            value
        );

        Ok(())
    }
}
