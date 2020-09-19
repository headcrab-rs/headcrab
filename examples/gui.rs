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
    use std::time::Instant;

    use clipboard::{ClipboardContext, ClipboardProvider};
    use glium::{
        glutin::event::Event, glutin::event::WindowEvent, glutin::event_loop::ControlFlow,
        glutin::event_loop::EventLoop, glutin::window::WindowBuilder, Display, Surface,
    };
    use headcrab::{
        symbol::DisassemblySource, symbol::RelocatedDwarf, target::LinuxTarget, target::UnixTarget,
    };
    use imgui::{im_str, ClipboardBackend, Direction, FontConfig, FontSource, ImStr, ImString};
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
        let builder = WindowBuilder::new().with_title("Headcrab");
        let display = Display::new(builder, context, &event_loop).unwrap();

        let mut platform = WinitPlatform::init(&mut imgui);
        platform.attach_window(
            imgui.io_mut(),
            display.gl_window().window(),
            HiDpiMode::Default,
        );

        imgui.fonts().add_font(&[FontSource::DefaultFontData {
            config: Some(FontConfig {
                size_pixels: (13.0 * platform.hidpi_factor()) as f32,
                ..FontConfig::default()
            }),
        }]);
        imgui.io_mut().font_global_scale = (1.0 / platform.hidpi_factor()) as f32;
        let mut renderer = Renderer::init(&mut imgui, &display).unwrap();

        let mut headcrab_ctx = HeadcrabContext::default();

        let mut last_frame = Instant::now();

        event_loop.run(move |event, _, control_flow| match event {
            Event::NewEvents(_) => {
                imgui.io_mut().update_delta_time(last_frame);
                last_frame = Instant::now();
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
            // FIXME only reload debuginfo when necessary (memory map changed)
            let memory_maps = self.remote()?.memory_maps()?;
            self.debuginfo = Some(RelocatedDwarf::from_maps(&memory_maps)?);
            Ok(())
        }

        fn debuginfo(&self) -> &RelocatedDwarf {
            self.debuginfo.as_ref().unwrap()
        }
    }

    fn render_gui(ui: &imgui::Ui, context: &mut HeadcrabContext) {
        if context.target_name.to_str() == "" {
            context.target_name.reserve(100); // FIXME workaround for imgui-rs#366
        }
        imgui::Window::new(im_str!("launch")).build(ui, || {
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
                }
                ui.same_line(0.0);
                if ui.small_button(im_str!("continue")) {
                    remote.unpause().unwrap();
                }
            } else {
                if ui.small_button(im_str!("launch")) {
                    context
                        .set_remote(LinuxTarget::launch(context.target_name.to_str()).unwrap().0);
                }
            }
        });
        if let Some(remote) = &context.remote {
            imgui::Window::new(im_str!("source")).build(ui, || {
                if let Err(err) = (|| -> Result<(), Box<dyn std::error::Error>> {
                    let ip = remote.read_regs()?.rip;
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
            imgui::Window::new(im_str!("backtrace")).build(ui, || {
                if let Err(err) = (|| -> Result<(), Box<dyn std::error::Error>> {
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

                    let regs = context.remote.as_ref().unwrap().read_regs()?;

                    let mut stack: [usize; 1024] = [0; 1024];
                    unsafe {
                        context
                            .remote
                            .as_ref()
                            .unwrap()
                            .read()
                            .read(&mut stack, regs.rsp as usize)
                            .apply()?;
                    }

                    let call_stack: Vec<_> = match context.backtrace_type {
                        BacktraceType::FramePtr => {
                            headcrab::symbol::unwind::frame_pointer_unwinder(
                                context.debuginfo(),
                                &stack[..],
                                regs.rip as usize,
                                regs.rsp as usize,
                                regs.rbp as usize,
                            )
                            .collect()
                        }
                        BacktraceType::Naive => headcrab::symbol::unwind::naive_unwinder(
                            context.debuginfo(),
                            &stack[..],
                            regs.rip as usize,
                        )
                        .collect(),
                    };

                    let mut frames_list = Vec::new();
                    for func in call_stack {
                        let res =
                            context
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
                                })?;
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
                    let frames_list = frames_list
                        .into_iter()
                        .map(ImString::from)
                        .collect::<Vec<_>>();
                    let frames_list = frames_list.iter().map(|f| &*f).collect::<Vec<_>>();
                    ui.list_box(im_str!("backtrace"), &mut 0, &*frames_list, 5);

                    Ok(())
                })() {
                    ui.text(format!("{}", err));
                }
            });
        }
    }
}
