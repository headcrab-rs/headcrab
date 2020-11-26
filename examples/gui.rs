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
    use std::{process::Command, time::Instant};

    use clipboard::{ClipboardContext, ClipboardProvider};
    use glium::{
        glutin::dpi::LogicalSize, glutin::event::Event, glutin::event::WindowEvent,
        glutin::event_loop::ControlFlow, glutin::event_loop::EventLoop,
        glutin::window::WindowBuilder, Display, Surface,
    };
    use headcrab::{
        symbol::DisassemblySource, symbol::RelocatedDwarf, target::LinuxTarget, target::Registers,
        target::UnixTarget, CrabResult,
    };
    use imgui::{im_str, ClipboardBackend, Condition, FontSource, ImStr, ImString};
    use imgui_glium_renderer::Renderer;
    use imgui_winit_support::{HiDpiMode, WinitPlatform};

    struct ClipboardSupport(ClipboardContext);

    impl ClipboardBackend for ClipboardSupport {
        fn get(&mut self) -> Option<ImString> {
            self.0.get_contents().ok().map(|text| text.into())
        }
        fn set(&mut self, text: &ImStr) {
            let _ = self.0.set_contents(text.to_str().to_owned());
        }
    }

    pub fn main() {
        let mut imgui = imgui::Context::create();
        imgui.set_clipboard_backend(Box::new(ClipboardSupport(ClipboardContext::new().unwrap())));

        let event_loop = EventLoop::new();
        let context = glium::glutin::ContextBuilder::new().with_vsync(true);
        let builder = WindowBuilder::new()
            .with_title("Headcrab")
            .with_inner_size(LogicalSize::new(800, 400));
        let display = Display::new(builder, context, &event_loop).unwrap();

        let mut platform = WinitPlatform::init(&mut imgui);
        platform.attach_window(
            imgui.io_mut(),
            display.gl_window().window(),
            HiDpiMode::Default,
        );

        imgui.fonts().add_font(&[FontSource::TtfData {
            data: include_bytes!("../fonts/FiraMono-Regular.ttf"),
            size_pixels: (13.0 * platform.hidpi_factor()) as f32,
            config: None,
        }]);
        imgui.io_mut().font_global_scale = (1.0 / platform.hidpi_factor()) as f32;
        imgui.io_mut().config_windows_move_from_title_bar_only = true;
        let mut renderer = Renderer::init(&mut imgui, &display).unwrap();

        let mut headcrab_ctx = HeadcrabContext::default();

        let mut last_frame = Instant::now();

        event_loop.run(move |event, _, control_flow| match event {
            Event::NewEvents(_) => {
                let now = Instant::now();
                imgui.io_mut().update_delta_time(now - last_frame);
                last_frame = now;
            }
            Event::MainEventsCleared => {
                platform
                    .prepare_frame(imgui.io_mut(), display.gl_window().window())
                    .unwrap();
                display.gl_window().window().request_redraw();
            }
            Event::RedrawRequested(_) => {
                let ui = imgui.frame();
                render_gui(&ui, &mut headcrab_ctx);

                let gl_window = display.gl_window();
                let mut target = display.draw();
                target.clear_color_srgb(1.0, 1.0, 1.0, 1.0);
                platform.prepare_render(&ui, gl_window.window());
                let draw_data = ui.render();
                renderer.render(&mut target, draw_data).unwrap();
                target.finish().unwrap();
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            event => {
                platform.handle_event(imgui.io_mut(), display.gl_window().window(), &event);
            }
        });
    }

    #[derive(Default)]
    struct HeadcrabContext {
        remote: Option<LinuxTarget>,
        debuginfo: Option<RelocatedDwarf>,
        disassembler: DisassemblySource,

        target_name: ImString,
        backtrace_type: BacktraceType,
        backtrace_selection: usize,
    }

    #[derive(Copy, Clone, PartialEq)]
    enum BacktraceType {
        // uses the frame_pointer_unwinder.
        FramePtr,

        // uses naive_unwinder.
        Naive,
    }

    impl Default for BacktraceType {
        fn default() -> Self {
            Self::FramePtr
        }
    }

    impl HeadcrabContext {
        fn remote(&self) -> CrabResult<&LinuxTarget> {
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

        fn reload_debuginfo(&mut self) -> CrabResult<()> {
            // FIXME only reload debuginfo when necessary (memory map changed)
            let memory_maps = self.remote()?.memory_maps()?;
            self.debuginfo = Some(RelocatedDwarf::from_maps(&memory_maps)?);
            Ok(())
        }

        fn load_debuginfo_if_necessary(&mut self) -> CrabResult<()> {
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

    fn render_gui(ui: &imgui::Ui, context: &mut HeadcrabContext) {
        context.target_name.reserve(100); // FIXME workaround for imgui-rs#366
        imgui::Window::new(im_str!("launch"))
            .position([5.0, 5.0], Condition::FirstUseEver)
            .size([390.0, 90.0], Condition::FirstUseEver)
            .build(ui, || {
                ui.input_text(im_str!("target"), &mut context.target_name)
                    .build();
                if let Some(remote) = &context.remote {
                    if ui.small_button(im_str!("kill")) {
                        remote.kill().unwrap();
                        context.remote = None;
                        return;
                    }
                    ui.same_line(0.0);
                    if ui.small_button(im_str!("step")) {
                        remote.step().unwrap();
                        // FIXME hack
                        let memory_maps = remote.memory_maps().unwrap();
                        context.debuginfo = Some(RelocatedDwarf::from_maps(&memory_maps).unwrap());
                    }
                    ui.same_line(0.0);
                    if ui.small_button(im_str!("continue")) {
                        remote.unpause().unwrap();
                        // FIXME hack
                        let memory_maps = remote.memory_maps().unwrap();
                        context.debuginfo = Some(RelocatedDwarf::from_maps(&memory_maps).unwrap());
                    }
                    ui.same_line(0.0);
                    if ui.small_button(im_str!("pbf")) {
                        patch_breakpoint_function(context).unwrap();
                    }
                } else {
                    if ui.small_button(im_str!("launch")) {
                        let cmd = Command::new(context.target_name.to_str());
                        context.set_remote(LinuxTarget::launch(cmd).unwrap().0);
                    }
                }
            });
        if let Some(remote) = &context.remote {
            imgui::Window::new(im_str!("source"))
                .position([400.0, 5.0], Condition::FirstUseEver)
                .size([395.0, 390.0], Condition::FirstUseEver)
                .build(ui, || {
                    if let Err(err) = (|| -> CrabResult<()> {
                        let ip = remote.read_regs()?.ip();
                        let mut code = [0; 64];
                        unsafe {
                            remote.read().read(&mut code, ip as usize).apply()?;
                        }
                        let disassembly = context.disassembler.source_snippet(&code, ip, true)?;
                        ui.text(disassembly);
                        Ok(())
                    })() {
                        ui.text(format!("{}", err));
                    }
                });
            imgui::Window::new(im_str!("backtrace"))
                .position([5.0, 100.0], Condition::FirstUseEver)
                .size([390.0, 295.0], Condition::FirstUseEver)
                .build(ui, || {
                    if let Err(err) = (|| -> CrabResult<()> {
                        ui.radio_button(
                            im_str!("frame-ptr"),
                            &mut context.backtrace_type,
                            BacktraceType::FramePtr,
                        );
                        ui.same_line(0.0);
                        ui.radio_button(
                            im_str!("naive"),
                            &mut context.backtrace_type,
                            BacktraceType::Naive,
                        );

                        context.load_debuginfo_if_necessary()?;

                        let regs = context
                            .remote
                            .as_ref()
                            .unwrap()
                            .main_thread()?
                            .read_regs()?;

                        let mut stack: [usize; 1024] = [0; 1024];
                        unsafe {
                            context
                                .remote
                                .as_ref()
                                .unwrap()
                                .read()
                                .read(&mut stack, regs.sp() as usize)
                                .apply()?;
                        }

                        let call_stack: Vec<_> = match context.backtrace_type {
                            BacktraceType::FramePtr => {
                                headcrab::symbol::unwind::frame_pointer_unwinder(
                                    context.debuginfo(),
                                    &stack[..],
                                    regs.ip() as usize,
                                    regs.sp() as usize,
                                    regs.bp().unwrap() as usize, // TODO: `unwrap` is unsafe for non-x86 platforms
                                )
                                .collect()
                            }
                            BacktraceType::Naive => headcrab::symbol::unwind::naive_unwinder(
                                context.debuginfo(),
                                &stack[..],
                                regs.ip() as usize,
                            )
                            .collect(),
                        };

                        let mut frames_list = Vec::new();
                        for func in call_stack {
                            let res = context.debuginfo().with_addr_frames(
                                func,
                                |_addr, mut frames| {
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
                                            frames_list.push(format!(
                                                "{:016x} {} {}",
                                                func, name, location
                                            ));
                                        } else {
                                            frames_list.push(format!(
                                                "                 {} {}",
                                                name, location
                                            ));
                                        }

                                        first_frame = false;
                                    }
                                    Ok(first_frame)
                                },
                            )?;
                            match res {
                                Some(true) | None => {
                                    frames_list.push(format!(
                                        "{:016x} at {}",
                                        func,
                                        context
                                            .debuginfo()
                                            .get_address_demangled_name(func)
                                            .as_deref()
                                            .unwrap_or("<unknown>")
                                    ));
                                }
                                Some(false) => {}
                            }
                        }

                        imgui::ChildWindow::new(im_str!("backtrace_list"))
                            .horizontal_scrollbar(true)
                            .build(ui, || {
                                for (i, frame) in frames_list.into_iter().enumerate() {
                                    let id = ui.push_id(&format!("backtrace_item_{}", i));
                                    if imgui::Selectable::new(&ImString::from(frame))
                                        .selected(i == context.backtrace_selection)
                                        .build(ui)
                                    {
                                        context.backtrace_selection = i;
                                    }
                                    id.pop(ui);
                                }
                            });

                        Ok(())
                    })() {
                        ui.text(format!("{}", err));
                    }
                });
        }
    }

    /// Patch the `pause` instruction inside a function called `breakpoint` to be a
    /// breakpoint. This is useful while we don't have support for setting breakpoints at
    /// runtime yet.
    /// FIXME remove once real breakpoint support is added
    fn patch_breakpoint_function(context: &mut HeadcrabContext) -> CrabResult<()> {
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

        Ok(())
    }
}
