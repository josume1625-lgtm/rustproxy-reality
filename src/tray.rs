//! Minimal Windows tray controller for the existing CLI executables.
#[cfg(not(windows))]
pub fn run(_: Option<&str>, _: bool, _: Option<fn() -> Result<Option<std::path::PathBuf>, Box<dyn std::error::Error>>>) -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "tray is available only on Windows").into())
}

#[cfg(windows)]
mod windows {
    use std::{cell::RefCell, error::Error, ffi::c_void, io, mem::{size_of, zeroed}, os::windows::{ffi::OsStrExt, process::CommandExt}, path::{Path, PathBuf}, process::Command, ptr};
    type Handle = *mut c_void;
    type Hwnd = Handle;
    type Wparam = usize;
    type Lparam = isize;
    type Lresult = isize;
    const WM_DESTROY: u32 = 2;
    const WM_TIMER: u32 = 0x113;
    const WM_APP_TRAY: u32 = 0x8001;
    const WM_RBUTTONUP: isize = 0x205;
    const WM_LBUTTONDBLCLK: isize = 0x203;
    const WAIT_OBJECT_0: u32 = 0;
    const CREATE_SUSPENDED: u32 = 4;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const SW_SHOWNORMAL: i32 = 1;

    #[repr(C)] struct Point { x: i32, y: i32 }
    #[repr(C)] struct Msg { hwnd: Hwnd, message: u32, wparam: Wparam, lparam: Lparam, time: u32, point: Point, private: u32 }
    #[repr(C)] struct WndClass { style: u32, proc: Option<unsafe extern "system" fn(Hwnd,u32,Wparam,Lparam)->Lresult>, cls_extra: i32, wnd_extra: i32, instance: Handle, icon: Handle, cursor: Handle, background: Handle, menu_name: *const u16, class_name: *const u16 }
    #[repr(C)] struct Guid { data1:u32, data2:u16, data3:u16, data4:[u8;8] }
    #[repr(C)] struct NotifyIcon { size:u32, hwnd:Hwnd, id:u32, flags:u32, callback:u32, icon:Handle, tip:[u16;128], state:u32, state_mask:u32, info:[u16;256], timeout_or_version:u32, info_title:[u16;64], info_flags:u32, guid:Guid, balloon_icon:Handle }
    #[repr(C)] struct StartupInfo { size:u32, reserved:*mut u16, desktop:*mut u16, title:*mut u16, x:u32,y:u32,xsize:u32,ysize:u32,xchars:u32,ychars:u32,fill:u32,flags:u32,show:u16,reserved2:u16, reserved_ptr:*mut u8, stdin:Handle, stdout:Handle, stderr:Handle }
    #[repr(C)] struct ProcessInfo { process:Handle, thread:Handle, process_id:u32, thread_id:u32 }
    #[repr(C)] struct BasicLimits { process_time:i64, job_time:i64, flags:u32, minimum:usize, maximum:usize, active_processes:u32, affinity:usize, priority:u32, scheduling:u32 }
    #[repr(C)] struct IoCounters { read_count:u64, write_count:u64, other_count:u64, read_bytes:u64, write_bytes:u64, other_bytes:u64 }
    #[repr(C)] struct ExtendedLimits { basic:BasicLimits, io:IoCounters, process_memory:usize, job_memory:usize, peak_process:usize, peak_job:usize }
    #[repr(C)] struct OpenFileName { size:u32, owner:Hwnd, instance:Handle, filter:*const u16, custom_filter:*mut u16, max_custom_filter:u32, filter_index:u32, file:*mut u16, max_file:u32, file_title:*mut u16, max_file_title:u32, initial_dir:*const u16, title:*const u16, flags:u32, file_offset:u16, file_extension:u16, default_ext:*const u16, custom_data:isize, hook:Handle, template_name:*const u16, reserved:Handle, reserved_word:u32, flags_ex:u32 }
    #[link(name="user32")] extern "system" {
        fn RegisterClassW(w:*const WndClass)->u16; fn CreateWindowExW(ex:u32, class:*const u16, title:*const u16, style:u32,x:i32,y:i32,w:i32,h:i32,parent:Hwnd,menu:Handle,instance:Handle,param:Handle)->Hwnd;
        fn DefWindowProcW(hwnd:Hwnd,msg:u32,w:Wparam,l:Lparam)->Lresult; fn DestroyWindow(hwnd:Hwnd)->i32; fn PostQuitMessage(code:i32);
        fn GetMessageW(msg:*mut Msg,hwnd:Hwnd,min:u32,max:u32)->i32; fn TranslateMessage(msg:*const Msg)->i32; fn DispatchMessageW(msg:*const Msg)->Lresult;
        fn LoadIconW(instance:Handle,name:*const u16)->Handle; fn MessageBoxW(hwnd:Hwnd,text:*const u16,caption:*const u16,kind:u32)->i32;
        fn CreatePopupMenu()->Handle; fn AppendMenuW(menu:Handle,flags:u32,id:usize,text:*const u16)->i32; fn TrackPopupMenu(menu:Handle,flags:u32,x:i32,y:i32,reserved:i32,hwnd:Hwnd,rect:Handle)->u32; fn DestroyMenu(menu:Handle)->i32;
        fn GetCursorPos(p:*mut Point)->i32; fn SetForegroundWindow(hwnd:Hwnd)->i32; fn SetTimer(hwnd:Hwnd,id:usize,interval:u32,callback:Handle)->usize;
        fn RegisterWindowMessageW(text:*const u16)->u32;
    }
    #[link(name="shell32")] extern "system" { fn Shell_NotifyIconW(message:u32,data:*mut NotifyIcon)->i32; fn ShellExecuteW(hwnd:Hwnd,op:*const u16,file:*const u16,params:*const u16,dir:*const u16,show:i32)->Handle; }
    #[link(name="comdlg32")] extern "system" { fn GetOpenFileNameW(data:*mut OpenFileName)->i32; }
    #[link(name="kernel32")] extern "system" {
        fn GetModuleHandleW(name:*const u16)->Handle; fn CreateJobObjectW(attr:Handle,name:*const u16)->Handle; fn SetInformationJobObject(job:Handle,class:u32,info:Handle,len:u32)->i32;
        fn CreateProcessW(app:*const u16,cmd:*mut u16,process_attr:Handle,thread_attr:Handle,inherit:i32,flags:u32,env:Handle,dir:*const u16,startup:*mut StartupInfo,process:*mut ProcessInfo)->i32;
        fn AssignProcessToJobObject(job:Handle,process:Handle)->i32; fn ResumeThread(thread:Handle)->u32; fn TerminateProcess(process:Handle,exit:u32)->i32; fn CloseHandle(handle:Handle)->i32;
        fn WaitForSingleObject(handle:Handle,millis:u32)->u32;
    }
    fn wide(s: &str)->Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }
    fn wide_path(s: &Path)->Vec<u16> { s.as_os_str().encode_wide().chain(Some(0)).collect() }
    fn message(hwnd:Hwnd, text:&str) { unsafe { MessageBoxW(hwnd,wide(text).as_ptr(),wide("RustProxy").as_ptr(),0x40); } }
    fn last_error(context:&str)->io::Error { io::Error::new(io::ErrorKind::Other,format!("{context}: {}",io::Error::last_os_error())) }
    struct Running { job:Handle, process:Handle }
    impl Running {
        fn is_alive(&self)->bool { unsafe { WaitForSingleObject(self.process,0) != WAIT_OBJECT_0 } }
    }
    impl Drop for Running { fn drop(&mut self) { unsafe { CloseHandle(self.job); CloseHandle(self.process); } } }
    type Wizard = fn() -> Result<Option<PathBuf>, Box<dyn Error>>;
    struct State { config:Option<PathBuf>, running:Option<Running>, running_http:Option<u64>, client:bool, proxy_on:bool, taskbar_msg:u32, wizard:Option<Wizard> }
    static mut STATE:*const RefCell<State> = ptr::null();
    fn launch(config:&Path)->Result<Running,Box<dyn Error>> {
        let exe=std::env::current_exe()?;
        let mut cmd=wide(&format!("\"{}\" run \"{}\"",exe.display(),config.display()));
        unsafe {
            let job=CreateJobObjectW(ptr::null_mut(),ptr::null());
            if job.is_null() { return Err(last_error("CreateJobObject").into()); }
            let mut limits:ExtendedLimits=zeroed(); limits.basic.flags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(job,9,&mut limits as *mut _ as Handle,size_of::<ExtendedLimits>() as u32)==0 { CloseHandle(job); return Err(last_error("SetInformationJobObject").into()); }
            let mut startup:StartupInfo=zeroed(); startup.size=size_of::<StartupInfo>() as u32;
            let mut proc:ProcessInfo=zeroed();
            if CreateProcessW(wide_path(&exe).as_ptr(),cmd.as_mut_ptr(),ptr::null_mut(),ptr::null_mut(),0,CREATE_SUSPENDED|CREATE_NO_WINDOW,ptr::null_mut(),ptr::null(),&mut startup,&mut proc)==0 { CloseHandle(job); return Err(last_error("CreateProcess").into()); }
            if AssignProcessToJobObject(job,proc.process)==0 { TerminateProcess(proc.process,1); CloseHandle(proc.thread); CloseHandle(proc.process); CloseHandle(job); return Err(last_error("AssignProcessToJobObject").into()); }
            if ResumeThread(proc.thread)==u32::MAX { TerminateProcess(proc.process,1); CloseHandle(proc.thread); CloseHandle(proc.process); CloseHandle(job); return Err(last_error("ResumeThread").into()); }
            CloseHandle(proc.thread);
            Ok(Running {job,process:proc.process})
        }
    }
    fn proxy_command(args:&[&str])->Result<(),String> {
        let exe=std::env::current_exe().map_err(|e|e.to_string())?;
        let result=Command::new(exe).arg("system-proxy").args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|e|e.to_string())?;
        if !result.status.success() { return Err(String::from_utf8_lossy(&result.stderr).trim().to_owned()); }
        Ok(())
    }
    fn restore_proxy(s:&mut State)->Result<(),String> { if s.proxy_on { proxy_command(&["off"])?; s.proxy_on=false; } Ok(()) }
    fn proxy_backup_exists()->bool {
        std::env::var_os("LOCALAPPDATA").or_else(||std::env::var_os("USERPROFILE"))
            .map(|root|PathBuf::from(root).join("rustproxy-system-proxy-backup.json").is_file()).unwrap_or(false)
    }
    fn proxy_ports(config:Option<&Path>)->Option<(u64,u64)> {
        let data=std::fs::read(config?).ok()?;
        let value:serde_json::Value=serde_json::from_slice(&data).ok()?;
        Some((value.get("socks_port")?.as_u64()?,value.get("http_port")?.as_u64()?))
    }
    fn state_path(client:bool)->io::Result<PathBuf> {
        let root=std::env::var_os("LOCALAPPDATA").or_else(||std::env::var_os("USERPROFILE"))
            .ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"cannot find the user settings directory"))?;
        Ok(PathBuf::from(root).join("RustProxy").join(if client {"client-tray-state.json"} else {"server-tray-state.json"}))
    }
    fn remember(s:&State)->Result<(),Box<dyn Error>> {
        let path=state_path(s.client)?;
        std::fs::create_dir_all(path.parent().ok_or_else(||io::Error::other("invalid settings path"))?)?;
        let config=s.config.as_ref().ok_or_else(||io::Error::other("no configuration selected"))?;
        let value=serde_json::json!({"config_path":config.to_string_lossy()});
        std::fs::write(path,serde_json::to_vec(&value)?)?;
        Ok(())
    }
    fn previous_config(client:bool)->Option<PathBuf> {
        let bytes=std::fs::read(state_path(client).ok()?).ok()?;
        let value:serde_json::Value=serde_json::from_slice(&bytes).ok()?;
        let path=PathBuf::from(value.get("config_path")?.as_str()?);
        if path.is_file() {Some(path)} else {None}
    }
    fn choose_config(hwnd:Hwnd,s:&mut State,path:PathBuf) {
        s.config=Some(path);
        if let Err(e)=remember(s) { message(hwnd,&format!("配置已选中，但无法保存路径，下次启动需重新选择：{e}")); }
    }
    fn start_selected(hwnd:Hwnd,s:&mut State) {
        if s.running.is_some() { message(hwnd,"已经在运行。"); return; }
        if let Some(path)=&s.config {
            let http=if s.client { proxy_ports(Some(path.as_path())).map(|(_,http)|http) } else {None};
            match launch(path) {
                Ok(process)=>{ s.running_http=http; s.running=Some(process); message(hwnd,"正在启动。可在托盘菜单中查看状态；启动失败时会提示。"); },
                Err(e)=>message(hwnd,&format!("启动失败：{e}")),
            }
        } else { message(hwnd,"请先选择配置文件。"); }
    }
    fn select_file(hwnd:Hwnd)->Option<PathBuf> {
        let mut buf=[0u16;32768]; let filter:Vec<u16>="JSON 配置\0*.json\0所有文件\0*.*\0\0".encode_utf16().collect();
        unsafe { let mut ofn:OpenFileName=zeroed(); ofn.size=size_of::<OpenFileName>() as u32; ofn.owner=hwnd; ofn.filter=filter.as_ptr(); ofn.file=buf.as_mut_ptr(); ofn.max_file=buf.len() as u32; ofn.flags=0x1000|0x800|0x8;
            if GetOpenFileNameW(&mut ofn)==0 { return None; }
        }
        let end=buf.iter().position(|&c|c==0).unwrap_or(buf.len());
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..end])))
    }
    fn icon(hwnd:Hwnd, action:u32) -> bool { unsafe { let mut data:NotifyIcon=zeroed(); data.size=size_of::<NotifyIcon>() as u32; data.hwnd=hwnd; data.id=1; data.flags=1|2|4; data.callback=WM_APP_TRAY; data.icon=LoadIconW(ptr::null_mut(),32512usize as *const u16); let tip=wide("RustProxy"); data.tip[..tip.len()].copy_from_slice(&tip); Shell_NotifyIconW(action,&mut data)!=0 } }
    fn menu(hwnd:Hwnd,s:&mut State) {
        unsafe {
            let menu=CreatePopupMenu(); if menu.is_null() { return; }
            let entries=[(9,"配置向导"),(1,"选择配置文件"),(2,"编辑当前配置"),(3,"启动"),(4,"停止"),(5,"查看状态"),(6,"启用 Windows 系统代理"),(7,"恢复 Windows 系统代理"),(8,"退出")];
            for (id,label) in entries { if (!s.client && (id==6 || id==7)) || (id==9 && s.wizard.is_none()) { continue; } AppendMenuW(menu,0,id,wide(label).as_ptr()); }
            let mut p:Point=zeroed(); GetCursorPos(&mut p); SetForegroundWindow(hwnd);
            let choice=TrackPopupMenu(menu,0x100|0x2,p.x,p.y,0,hwnd,ptr::null_mut()); DestroyMenu(menu);
            match choice {
                9 => if s.running.is_some() { message(hwnd,"请先停止运行，再打开配置向导。"); } else if let Some(wizard)=s.wizard { match wizard() { Ok(Some(path))=>{choose_config(hwnd,s,path);start_selected(hwnd,s);}, Ok(None)=>(), Err(e)=>message(hwnd,&format!("配置向导失败：{e}")) } },
                1 => if s.running.is_some() { message(hwnd,"请先停止运行，再切换配置。"); } else if let Some(path)=select_file(hwnd) { choose_config(hwnd,s,path); },
                2 => if s.running.is_some() { message(hwnd,"请先停止运行，再编辑配置。"); } else if let Some(path)=&s.config { let rc=ShellExecuteW(hwnd,wide("open").as_ptr(),wide_path(path).as_ptr(),ptr::null(),ptr::null(),SW_SHOWNORMAL) as isize; if rc<=32 { message(hwnd,"无法打开配置文件。请手动使用文本编辑器打开。"); } } else { message(hwnd,"请先选择配置文件。"); },
                3 => start_selected(hwnd,s),
                4 => { if let Err(e)=restore_proxy(s) { message(hwnd,&format!("恢复系统代理失败，备份已保留：{e}")); } s.running=None; s.running_http=None; },
                5 => { let state=if s.running.as_ref().is_some_and(Running::is_alive) { "运行中" } else { "已停止" }; let name=s.config.as_ref().map(|p|p.display().to_string()).unwrap_or_else(||"未选择".into()); let ports=if s.client { proxy_ports(s.config.as_deref()).map(|(socks,http)|format!("\nSOCKS5：127.0.0.1:{socks}\nHTTP：127.0.0.1:{http}")).unwrap_or_default() } else { String::new() }; message(hwnd,&format!("状态：{state}\n配置：{name}{ports}\n本次托盘启用系统代理：{}\n代理备份存在：{}",if s.proxy_on {"是"} else {"否"},if proxy_backup_exists(){"是"}else{"否"})); },
                6 => if !s.running.as_ref().is_some_and(Running::is_alive) { message(hwnd,"请先启动客户端。"); } else if let Some(path)=&s.config {
                    let port=proxy_ports(Some(path.as_path())).map(|(_,p)|p).filter(|p|(1..=65535).contains(p));
                    if port!=s.running_http { message(hwnd,"配置中的 HTTP 端口已改变；请停止客户端并重新启动。"); }
                    else if let Some(port)=port {
                        let addr=std::net::SocketAddr::from(([127,0,0,1],port as u16));
                        if std::net::TcpStream::connect_timeout(&addr,std::time::Duration::from_millis(500)).is_err() { message(hwnd,"客户端 HTTP 端口尚未监听，请检查配置或稍后重试。"); }
                        else { match proxy_command(&["on",&port.to_string()]) { Ok(())=>{s.proxy_on=true;message(hwnd,"系统代理已启用。");},Err(e)=>message(hwnd,&format!("启用失败：{e}")) } }
                    } else { message(hwnd,"配置中没有有效的 http_port。"); }
                },
                7 => if !proxy_backup_exists() { message(hwnd,"没有找到代理备份，无需恢复。"); } else if let Err(e)=proxy_command(&["off"]) { message(hwnd,&format!("恢复失败，备份已保留：{e}")); } else { s.proxy_on=false; message(hwnd,"系统代理已恢复。"); },
                8 => { if let Err(e)=restore_proxy(s) { message(hwnd,&format!("恢复系统代理失败，备份已保留，请手动运行 system-proxy off：{e}")); } s.running=None; DestroyWindow(hwnd); },
                _=>()
            }
        }
    }
    unsafe extern "system" fn window_proc(hwnd:Hwnd,msg:u32,w:Wparam,l:Lparam)->Lresult {
        if !STATE.is_null() {
          if let Ok(mut guard)=(*STATE).try_borrow_mut() {
            let s=&mut *guard;
            if msg==s.taskbar_msg { icon(hwnd,0); return 0; }
            if msg==WM_APP_TRAY && (l==WM_RBUTTONUP || l==WM_LBUTTONDBLCLK) { menu(hwnd,s); return 0; }
            if msg==WM_TIMER && s.running.as_ref().is_some_and(|p|!p.is_alive()) { if let Err(e)=restore_proxy(s) { message(hwnd,&format!("客户端退出，恢复系统代理失败，备份已保留：{e}")); } s.running=None; s.running_http=None; message(hwnd,"后台进程已退出。可能是端口占用或配置错误，请重新选择端口，或使用命令行 run 查看详细诊断。"); return 0; }
          }
        }
        if msg==WM_DESTROY { icon(hwnd,2); PostQuitMessage(0); return 0; }
        DefWindowProcW(hwnd,msg,w,l)
    }
    pub fn run(config:Option<&str>,client:bool,wizard:Option<Wizard>)->Result<(),Box<dyn Error>> {
        let explicit=config.map(|p|std::env::current_dir().map(|d|d.join(p))).transpose()?;
        let remembered=if explicit.is_none() { previous_config(client) } else {None};
        let autostart=remembered.is_some();
        let config=explicit.or(remembered);
        let state=Box::new(RefCell::new(State {config,running:None,running_http:None,client,proxy_on:false,taskbar_msg:unsafe{RegisterWindowMessageW(wide("TaskbarCreated").as_ptr())},wizard}));
        unsafe {
            STATE=&*state;
            let class=wide("RustProxyTrayWindow"); let instance=GetModuleHandleW(ptr::null());
            let wc=WndClass {style:0,proc:Some(window_proc),cls_extra:0,wnd_extra:0,instance,icon:ptr::null_mut(),cursor:ptr::null_mut(),background:ptr::null_mut(),menu_name:ptr::null(),class_name:class.as_ptr()};
            if RegisterClassW(&wc)==0 { STATE=ptr::null(); return Err(last_error("RegisterClass").into()); }
            let hwnd=CreateWindowExW(0,class.as_ptr(),wide("RustProxy").as_ptr(),0,0,0,0,0,ptr::null_mut(),ptr::null_mut(),instance,ptr::null_mut());
            if hwnd.is_null() { STATE=ptr::null(); return Err(last_error("CreateWindow").into()); }
            if !icon(hwnd,0) { DestroyWindow(hwnd); STATE=ptr::null(); return Err(last_error("Shell_NotifyIcon").into()); }
            SetTimer(hwnd,1,1000,ptr::null_mut());
            if client && proxy_backup_exists() {
                let choice=MessageBoxW(hwnd,wide("检测到以前遗留的系统代理备份。现在尝试恢复原设置吗？").as_ptr(),wide("RustProxy").as_ptr(),0x34);
                if choice==6 { match proxy_command(&["off"]) { Ok(())=>message(hwnd,"系统代理已恢复。"), Err(e)=>message(hwnd,&format!("恢复失败，备份已保留：{e}")) } }
            }
            let (needs_config, startup_wizard)={ let s=state.borrow(); (s.config.is_none(), s.wizard) };
            if autostart { start_selected(hwnd,&mut state.borrow_mut()); }
            else if needs_config {
                if let Some(wizard)=startup_wizard {
                    message(hwnd,"欢迎使用 RustProxy。现在打开配置向导；取消后可右键托盘图标重新打开。");
                    match wizard() { Ok(Some(path))=>{ let mut s=state.borrow_mut(); choose_config(hwnd,&mut s,path); start_selected(hwnd,&mut s); }, Ok(None)=>(), Err(e)=>message(hwnd,&format!("配置向导失败：{e}")) }
                } else { message(hwnd,"RustProxy 已进入系统托盘。右键托盘图标选择配置文件并启动。"); }
            }
            let mut msg:Msg=zeroed();
            loop { let result=GetMessageW(&mut msg,ptr::null_mut(),0,0); if result<=0 { break; } TranslateMessage(&msg); DispatchMessageW(&msg); }
            let mut s=state.borrow_mut(); if s.proxy_on { if let Err(e)=restore_proxy(&mut s) { message(ptr::null_mut(),&format!("恢复系统代理失败，备份已保留，请手动运行 system-proxy off：{e}")); } }
            s.running=None; STATE=ptr::null();
        }
        Ok(())
    }
}
#[cfg(windows)]
pub fn run(config:Option<&str>,client:bool,wizard:Option<fn() -> Result<Option<std::path::PathBuf>, Box<dyn std::error::Error>>>)->Result<(),Box<dyn std::error::Error>> { windows::run(config,client,wizard) }
