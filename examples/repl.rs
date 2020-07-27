use headcrab::target::{LinuxTarget, UnixTarget};

struct Context {
    remote: Option<LinuxTarget>,
}

impl Context {
    fn remote(&self) -> Result<&LinuxTarget, Box<dyn std::error::Error>> {
        if let Some(remote) = &self.remote {
            Ok(remote)
        } else {
            Err("No running process".to_string().into())
        }
    }
}

fn main() {
    let mut rl = rustyline::Editor::<()>::with_config(
        rustyline::Config::builder().auto_add_history(true).build(),
    );
    let mut context = Context { remote: None };

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
            _ if arg.starts_with("-") => format!("Found argument '{}' which wasn't expected", arg),
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
        context.remote = Some(match LinuxTarget::launch(&exec_cmd) {
            Ok(target) => target,
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
                context.remote = Some(LinuxTarget::launch(cmd)?);
            }
        }
        Some("attach") => {
            if let Some(pid) = parts.next() {
                let pid = nix::unistd::Pid::from_raw(pid.parse()?);
                println!("Attaching to process {}", pid);
                context.remote = Some(LinuxTarget::attach(pid)?);
            }
        }
        Some("cont") => context.remote()?.unpause()?,
        Some("regs") => match parts.next() {
            Some("read") => println!("{:?}", context.remote()?.read_regs()?),
            Some(sub) => Err(format!("Unknown `regs` subcommand `{}`", sub))?,
            None => Err(format!(
                "Expected subcommand found nothing. Try `regs read`"
            ))?,
        },
        Some("") | None => {}
        Some(command) => Err(format!("Unknown command `{}`", command))?,
    }

    Ok(())
}
