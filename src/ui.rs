use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_gpucodec(&self) -> bool {
        has_gpucodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_gpucodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding TTODO Image settings in this location
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
