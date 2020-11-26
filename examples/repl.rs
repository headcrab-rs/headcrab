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
    use std::{borrow::Cow, process::Command};
    use std::{os::unix::ffi::OsStrExt, path::PathBuf};

    use headcrab::{
        symbol::{DisassemblySource, RelocatedDwarf, Snippet},
        target::{AttachOptions, LinuxTarget, Registers, UnixTarget},
        CrabResult,
    };

    #[cfg(target_os = "linux")]
    use headcrab_inject::{inject_clif_code, DataId, FuncId, InjectionModule};

    use repl_tools::HighlightAndComplete;
    use rustyline::{completion::Pair, CompletionType};

    repl_tools::define_repl_cmds!(enum ReplCommand {
        err = ReplCommandError;

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
        /// Set a breakpoint at symbol or address
        Breakpoint|b: String,
        // FIXME move the `read:` part before the `--` in the help
        /// read: List registers and their content for the current stack frame
        Registers|regs: String,
        /// Print backtrace of stack frames
        Backtrace|bt: BacktraceType,
        /// Disassemble some a several instructions starting at the instruction pointer
        Disassemble|dis: (),
        /// Print all local variables of current stack frame
        Locals: (),
        /// Print this help
        Help|h: (),
        /// Inject and run clif ir
        InjectClif: PathBuf,
        /// Inject a dynamic library and run it's `__headcrab_command` function
        InjectLib: PathBuf,
        /// Print the source code execution point.
        List|l: (),
        /// Exit
        Exit|quit|q: (),
    });

    type ReplHelper = repl_tools::MakeHelper<ReplCommand>;

    #[derive(Default)]
    struct Context {
        remote: Option<LinuxTarget>,
        debuginfo: Option<RelocatedDwarf>,
        disassembler: DisassemblySource,
    }

    /// The subcommands that are acceptable for backtrace.
    enum BacktraceType {
        // uses the frame_pointer_unwinder.
        FramePtr,

        // uses naive_unwinder.
        Naive,
    }

    #[derive(Debug)]
    struct BacktraceTypeError(String);

    impl std::fmt::Display for BacktraceTypeError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Unrecognized backtrace type {}. Supported ones are 'fp' and 'naive'. Please consider using one of them.", self.0.trim())
        }
    }
    impl std::error::Error for BacktraceTypeError {}

    impl BacktraceType {
        #[inline]
        fn from_str(value: &str) -> Result<Self, BacktraceTypeError> {
            match value {
                "fp" | "" => Ok(BacktraceType::FramePtr),
                "naive" => Ok(BacktraceType::Naive),
                _ => Err(BacktraceTypeError(value.to_owned()).into()),
            }
        }
    }

    impl Default for BacktraceType {
        fn default() -> Self {
            BacktraceType::FramePtr
        }
    }

    impl HighlightAndComplete for BacktraceType {
        type Error = BacktraceTypeError;
        fn from_str(line: &str) -> Result<Self, Self::Error> {
            BacktraceType::from_str(line.trim())
        }

        fn highlight<'l>(line: &'l str) -> Cow<'l, str> {
            line.into()
        }

        fn complete(
            line: &str,
            pos: usize,
            ctx: &rustyline::Context<'_>,
        ) -> rustyline::Result<(usize, Vec<Pair>)> {
            let pos_first_non_whitespace = line
                .chars()
                .position(|c| !c.is_ascii_whitespace())
                .unwrap_or(0);

            let candidates = ["fp", "naive"]
                .iter()
                .filter(|&&cmd| cmd.starts_with(&line.trim_start().to_lowercase()))
                .map(|cmd| Pair {
                    display: String::from(*cmd),
                    replacement: String::from(*cmd) + " ",
                })
                .collect::<Vec<_>>();

            let _ = (line, pos, ctx);
            return Ok((pos_first_non_whitespace, candidates));
        }
    }

    impl Context {
        fn remote(&self) -> CrabResult<&LinuxTarget> {
            if let Some(remote) = &self.remote {
                Ok(remote)
            } else {
                Err("No running process".to_string().into())
            }
        }

        fn mut_remote(&mut self) -> CrabResult<&mut LinuxTarget> {
            if let Some(remote) = &mut self.remote {
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

        fn load_debuginfo_if_necessary(&mut self) -> CrabResult<()> {
            // FIXME only reload debuginfo when necessary (memory map changed)
            let memory_maps = self.remote()?.memory_maps()?;
            self.debuginfo = Some(RelocatedDwarf::from_maps(&memory_maps)?);
            Ok(())
        }

        fn debuginfo(&self) -> &RelocatedDwarf {
            self.debuginfo.as_ref().unwrap()
        }
    }

    pub fn main() {
        let mut rl = rustyline::Editor::<ReplHelper>::with_config(
            rustyline::Config::builder()
                .auto_add_history(true)
                .completion_type(CompletionType::List)
                .build(),
        );
        rl.set_helper(Some(ReplHelper::new(true /* color */)));

        let mut context = Context::default();

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
                    rl.helper_mut().unwrap().color = false;
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
            context.set_remote(match LinuxTarget::launch(Command::new(exec_cmd)) {
                Ok((target, status)) => {
                    println!("{:?}", status);
                    target
                }
                Err(err) => {
                    if rl.helper().unwrap().color {
                        println!("\x1b[91mError while launching debuggee: {}\x1b[0m", err);
                    } else {
                        println!("Error while launching debuggee: {}", err);
                    }
                    std::process::exit(1);
                }
            });
        }

        for command in cmds.into_iter() {
            if rl.helper().unwrap().color {
                println!("\x1b[96m> {}\x1b[0m", command);
            } else {
                println!("> {}", command);
            }
            match run_command(&mut context, rl.helper().unwrap().color, &command) {
                Ok(()) => {}
                Err(err) => {
                    if rl.helper().unwrap().color {
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
                    match run_command(&mut context, rl.helper().unwrap().color, &command) {
                        Ok(()) => {}
                        Err(err) => {
                            if rl.helper().unwrap().color {
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
                    if rl.helper().unwrap().color {
                        println!("\x1b[91mError: {:?}\x1b[0m", err);
                    } else {
                        println!("Error: {:?}", err);
                    }
                    std::process::exit(1);
                }
            }
        }
    }

    fn run_command(context: &mut Context, color: bool, command: &str) -> CrabResult<()> {
        if command == "" {
            return Ok(());
        }

        let command = ReplCommand::from_str(command)?;
        match command {
            ReplCommand::Help(()) => {
                ReplCommand::print_help(std::io::stdout(), color).unwrap();
            }
            ReplCommand::Exec(cmd) => {
                println!("Starting program: {}", cmd.display());
                let (remote, status) = LinuxTarget::launch(Command::new(cmd))?;
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
            ReplCommand::Breakpoint(location) => set_breakpoint(context, &location)?,
            ReplCommand::Stepi(()) => {
                println!("{:?}", context.remote()?.step()?);
                return print_source_for_top_of_stack_symbol(context, 3);
            }
            ReplCommand::Continue(()) => {
                println!("{:?}", context.remote()?.unpause()?);
                // When we hit the next breakpoint, we also want to display the source code
                // as lldb and gdb does.
                return print_source_for_top_of_stack_symbol(context, 3);
            }
            ReplCommand::Registers(sub_cmd) => match &*sub_cmd {
                "" => Err(format!(
                    "Expected subcommand found nothing. Try `regs read`"
                ))?,
                "read" => println!("{:#016x?}", context.remote()?.read_regs()?),
                _ => Err(format!("Unknown `regs` subcommand `{}`", sub_cmd))?,
            },
            ReplCommand::Backtrace(sub_cmd) => {
                return show_backtrace(context, &sub_cmd);
            }
            ReplCommand::Disassemble(()) => {
                let ip = context.remote()?.read_regs()?.ip();
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
            ReplCommand::List(()) => {
                return print_source_for_top_of_stack_symbol(context, 3);
            }
            ReplCommand::Locals(()) => {
                return show_locals(context);
            }
            ReplCommand::InjectClif(file) => {
                return inject_clif(context, file);
            }
            ReplCommand::InjectLib(file) => {
                return inject_lib(context, file);
            }
            ReplCommand::Exit(()) => unreachable!("Should be handled earlier"),
        }
        Ok(())
    }

    fn set_breakpoint(context: &mut Context, location: &str) -> CrabResult<()> {
        context.load_debuginfo_if_necessary()?;

        if let Ok(addr) = {
            usize::from_str_radix(&location, 10)
                .map(|addr| addr as usize)
                .map_err(|e| Box::new(e))
                .or_else(|_e| {
                    if location.starts_with("0x") {
                        let raw_num = location.trim_start_matches("0x");
                        usize::from_str_radix(raw_num, 16)
                            .map(|addr| addr as usize)
                            .map_err(|_e| Box::new(format!("Invalid address format.")))
                    } else {
                        context
                            .debuginfo()
                            .get_symbol_address(&location)
                            .ok_or(Box::new(format!("No such symbol {}", location)))
                    }
                })
        } {
            context.mut_remote()?.set_breakpoint(addr)?;
        } else {
            Err(format!(
                "Breakpoints must be set on a symbol or at a given address. For example `b main` or `b 0x0000555555559394` or even `b 93824992252820`"
            ))?
        }
        Ok(())
    }

    fn show_backtrace(context: &mut Context, bt_type: &BacktraceType) -> CrabResult<()> {
        let call_stack: Vec<_> = get_call_stack(context, bt_type)?;
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
        Ok(())
    }

    fn show_locals(context: &mut Context) -> CrabResult<()> {
        let regs = context.remote()?.main_thread()?.read_regs()?;
        let func = regs.ip() as usize;
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

                    let mut eval_ctx = EvalContext {
                        frame_base: None,
                        regs: Box::new(regs),
                    };

                    // FIXME handle DW_TAG_inlined_subroutine with DW_AT_frame_base in parent DW_TAG_subprogram
                    if let Some(frame_base) =
                        unit.entry(dw_die_offset)?.attr(gimli::DW_AT_frame_base)?
                    {
                        let frame_base = frame_base.exprloc_value().unwrap();
                        let res = headcrab::symbol::dwarf_utils::evaluate_expression(
                            unit, frame_base, &eval_ctx,
                        )?;
                        assert_eq!(res.len(), 1);
                        assert_eq!(res[0].bit_offset, None);
                        assert_eq!(res[0].size_in_bits, None);
                        match res[0].location {
                            gimli::Location::Register {
                                register: gimli::X86_64::RBP,
                            } => eval_ctx.frame_base = regs.bp(),
                            ref loc => unimplemented!("{:?}", loc), // FIXME
                        }
                    }

                    frame.each_argument(&eval_ctx, func as u64, |local| {
                        show_local("arg", &eval_ctx, local)
                    })?;

                    frame.each_local(&eval_ctx, func as u64, |local| {
                        show_local("    ", &eval_ctx, local)
                    })?;

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

        Ok(())
    }

    fn get_call_stack(context: &mut Context, bt_type: &BacktraceType) -> CrabResult<Vec<usize>> {
        context.load_debuginfo_if_necessary()?;

        let regs = context.remote()?.main_thread()?.read_regs()?;

        let mut stack: [usize; 1024] = [0; 1024];
        unsafe {
            context
                .remote()?
                .read()
                .read(&mut stack, regs.sp() as usize)
                .apply()?;
        }

        let call_stack: Vec<_> = match *bt_type {
            BacktraceType::FramePtr => headcrab::symbol::unwind::frame_pointer_unwinder(
                context.debuginfo(),
                &stack[..],
                regs.ip() as usize,
                regs.sp() as usize,
                regs.bp().unwrap() as usize, // TODO: fix `unwrap` for non-x86 platforms
            )
            .collect(),
            BacktraceType::Naive => headcrab::symbol::unwind::naive_unwinder(
                context.debuginfo(),
                &stack[..],
                regs.ip() as usize,
            )
            .collect(),
        };
        Ok(call_stack)
    }

    /// Gets the call_stack from the context and then tries to display the
    /// source for the top call in the stack. Because the first frame is usually
    /// sse2.rs, we just display the file and line but not the source and we skip
    /// over to the next frame. For the next frame, we will display the source code.
    /// An example view is shown below:
    ///
    /// It marks the line with the berakpoint with a '>' character and shows some lines
    /// of context above and below it.
    ///
    /// ```plain
    /// 0000555555559295 core::core_arch::x86::sse2::_mm_pause /../rustup/toolchains/1.45.2-x86_64-unknown-linux-gnu/../stdarch/crates/core_arch/src/x86/sse2.rs:25
    /// /workspaces/headcrab/tests/testees/hello.rs:7:14
    ///    4 #[inline(never)]
    ///    5 fn breakpoint() {
    ///    6     // This will be patched by the debugger to be a breakpoint
    /// >  7     unsafe { core::arch::x86_64::_mm_pause(); }
    ///    8 }
    ///    9
    ///   10 #[inline(never)]
    /// ```
    fn print_source_for_top_of_stack_symbol(
        context: &mut Context,
        context_lines: usize,
    ) -> CrabResult<()> {
        let call_stack = get_call_stack(context, &BacktraceType::default())?;
        let top_of_stack = call_stack[0];
        context
            .debuginfo()
            .with_addr_frames(top_of_stack, |_addr, mut frames| {
                while let Some(frame) = frames.next()? {
                    let name = frame
                        .function
                        .as_ref()
                        .map(|f| Ok(f.demangle()?.into_owned()))
                        .transpose()
                        .map_err(|err: gimli::Error| err)?
                        .unwrap_or_else(|| "<unknown>".to_string());

                    let (file, line, column) = frame
                        .location
                        .as_ref()
                        .map(|loc| {
                            (
                                loc.file.unwrap_or("<unknown file>"),
                                loc.line.unwrap_or(0),
                                loc.column.unwrap_or(0),
                            )
                        })
                        .unwrap_or_default();
                    Snippet::from_file(
                        file,
                        name,
                        line as usize,
                        context_lines as usize,
                        column as usize,
                    )?
                    .highlight();
                    break;
                }
                Ok(())
            })?;
        Ok(())
    }

    struct EvalContext {
        frame_base: Option<u64>,
        regs: Box<dyn headcrab::target::Registers>,
    }

    impl headcrab::symbol::dwarf_utils::EvalContext for EvalContext {
        fn frame_base(&self) -> u64 {
            self.frame_base.unwrap()
        }

        fn register(&self, register: gimli::Register, base_type: gimli::ValueType) -> gimli::Value {
            let val = self.regs.reg_for_dwarf(register).unwrap();
            match base_type {
                gimli::ValueType::Generic => gimli::Value::Generic(val),
                gimli::ValueType::U64 => gimli::Value::U64(val),
                _ => unimplemented!(),
            }
        }

        fn memory(
            &self,
            _address: u64,
            _size: u8,
            _address_space: Option<u64>,
            _base_type: gimli::ValueType,
        ) -> gimli::Value {
            todo!()
        }
    }

    fn show_local<'ctx>(
        kind: &str,
        eval_ctx: &EvalContext,
        local: headcrab::symbol::Local<'_, 'ctx>,
    ) -> CrabResult<()> {
        let value = match local.value() {
            value @ headcrab::symbol::LocalValue::Pieces(_)
            | value @ headcrab::symbol::LocalValue::Const(_) => {
                match value.primitive_value(local.type_(), eval_ctx)? {
                    Some(headcrab::symbol::PrimitiveValue::Int { size, signed, data }) => {
                        if signed {
                            (data << (64 - size * 8) >> (64 - size * 8)).to_string()
                        } else {
                            ((data as i64) << (64 - size * 8) >> (64 - size * 8)).to_string()
                        }
                    }
                    Some(headcrab::symbol::PrimitiveValue::Float { is_64, data }) => {
                        if is_64 {
                            f64::from_bits(data).to_string()
                        } else {
                            f32::from_bits(data as u32).to_string()
                        }
                    }
                    None => "<struct>".to_owned(),
                }
            }
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

    #[cfg(not(target_os = "linux"))]
    fn inject_clif(_context: &mut Context, _file: PathBuf) -> CrabResult<()> {
        Err("injectclif is currently only supported on Linux"
            .to_string()
            .into())
    }

    #[cfg(target_os = "linux")]
    fn inject_clif(context: &mut Context, file: PathBuf) -> CrabResult<()> {
        context.load_debuginfo_if_necessary()?;

        let mut inj_ctx = InjectionModule::new(context.remote()?)?;
        let run_function = inject_clif_code(
            &mut inj_ctx,
            &|sym| context.debuginfo().get_symbol_address(sym).unwrap() as u64,
            &std::fs::read_to_string(file)?,
        )?;

        let stack = inj_ctx.new_stack(0x1000)?;

        println!(
            "run function: 0x{:016x} stack: 0x{:016x}",
            run_function, stack
        );

        // TODO: replace `main_thread` with the current thread when we'll have it.
        let orig_regs = inj_ctx.target().main_thread()?.read_regs()?;
        let mut regs = orig_regs.clone();
        regs.set_ip(run_function);
        regs.set_sp(stack);
        inj_ctx.target().main_thread()?.write_regs(regs)?;

        let status = inj_ctx.target().unpause()?;
        println!(
            "{:?} at 0x{:016x}",
            status,
            inj_ctx.target().read_regs()?.ip()
        );
        inj_ctx.target().main_thread()?.write_regs(orig_regs)?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn inject_lib(_context: &mut Context, _file: PathBuf) -> CrabResult<()> {
        Err("injectclif is currently only supported on Linux"
            .to_string()
            .into())
    }

    #[cfg(target_os = "linux")]
    fn inject_lib(context: &mut Context, file: PathBuf) -> CrabResult<()> {
        context.load_debuginfo_if_necessary()?;

        let mut inj_ctx = InjectionModule::new(context.remote()?)?;
        inj_ctx.define_function(
            FuncId::from_u32(0),
            context.debuginfo().get_symbol_address("dlopen").unwrap() as u64,
        );
        inj_ctx.define_function(
            FuncId::from_u32(1),
            context.debuginfo().get_symbol_address("dlsym").unwrap() as u64,
        );

        let mut file = file.canonicalize()?.as_os_str().as_bytes().to_owned();
        file.push(0);
        inj_ctx.define_data_object_with_bytes(DataId::from_u32(0), &file)?;

        inj_ctx.define_data_object_with_bytes(DataId::from_u32(1), b"__headcrab_command\0")?;

        let isa = headcrab_inject::target_isa();

        let functions =
            headcrab_inject::parse_functions(include_str!("./inject_dylib.clif")).unwrap();
        let mut ctx = headcrab_inject::Context::new();
        for func in functions {
            ctx.clear();
            ctx.func = func;
            inj_ctx.compile_clif_code(&*isa, &mut ctx)?;
        }

        let run_function = inj_ctx.lookup_function(FuncId::from_u32(2));
        let stack = inj_ctx.new_stack(0x1000)?;
        println!(
            "run function: 0x{:016x} stack: 0x{:016x}",
            run_function, stack
        );

        let orig_regs = inj_ctx.target().main_thread()?.read_regs()?;
        println!("orig rip: {:016x}", orig_regs.ip());

        let mut regs = orig_regs.clone();
        regs.set_ip(run_function);
        regs.set_sp(stack);
        inj_ctx.target().main_thread()?.write_regs(regs)?;

        let status = inj_ctx.target().unpause()?;
        println!(
            "{:?} at 0x{:016x}",
            status,
            inj_ctx.target().main_thread()?.read_regs()?.ip()
        );
        inj_ctx.target().main_thread()?.write_regs(orig_regs)?;

        Ok(())
    }
}
