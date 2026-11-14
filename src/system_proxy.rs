use std::error::Error;

#[cfg(not(windows))]
pub fn run(_args: &[String]) -> Result<(), Box<dyn Error>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "system proxy is available only on Windows").into())
}

#[cfg(windows)]
mod windows {
    use serde_json::{json, Value};
    use std::{error::Error, fs::{self, OpenOptions}, io::{self, Write}, path::PathBuf};
    use winreg::{enums::*, RegKey, RegValue};

    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const NAMES: [&str; 3] = ["ProxyEnable", "ProxyServer", "AutoConfigURL"];

    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(handle: *mut std::ffi::c_void, option: u32, buffer: *mut std::ffi::c_void, length: u32) -> i32;
    }

    fn refresh() -> Result<()> {
        for option in [39, 37] { // SETTINGS_CHANGED, REFRESH
            if unsafe { InternetSetOptionW(std::ptr::null_mut(), option, std::ptr::null_mut(), 0) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    fn path() -> Result<PathBuf> {
        let root = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot locate user directory"))?;
        Ok(PathBuf::from(root).join("rustproxy-system-proxy-backup.json"))
    }

    fn key() -> io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(SUBKEY, KEY_READ | KEY_WRITE)
    }

    fn raw_optional(key: &RegKey, name: &str) -> io::Result<Option<RegValue>> {
        match key.get_raw_value(name) {
            Ok(value) => Ok(Some(value)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn value_type(id: u64) -> Result<RegType> {
        let t = match id {
            0 => REG_NONE, 1 => REG_SZ, 2 => REG_EXPAND_SZ, 3 => REG_BINARY,
            4 => REG_DWORD, 5 => REG_DWORD_BIG_ENDIAN, 6 => REG_LINK,
            7 => REG_MULTI_SZ, 8 => REG_RESOURCE_LIST, 9 => REG_FULL_RESOURCE_DESCRIPTOR,
            10 => REG_RESOURCE_REQUIREMENTS_LIST, 11 => REG_QWORD,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown registry type in proxy backup").into()),
        };
        Ok(t)
    }

    fn snapshot(key: &RegKey, applied: &str) -> Result<Value> {
        let mut map = serde_json::Map::new();
        for name in NAMES {
            let v = match raw_optional(key, name)? {
                Some(v) => json!({"type": v.vtype as u32, "bytes": v.bytes}),
                None => Value::Null,
            };
            map.insert(name.into(), v);
        }
        Ok(json!({"version": 1, "values": map, "applied_server": applied}))
    }

    fn restore(key: &RegKey, data: &Value) -> Result<()> {
        if data.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid proxy backup version").into());
        }
        let values = data.get("values").and_then(Value::as_object)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proxy backup"))?;
        // Parse all fields before touching the registry, so a corrupt backup cannot partly restore.
        let mut restored = Vec::new();
        for name in NAMES {
            let value = values.get(name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "incomplete proxy backup"))?;
            if value.is_null() { restored.push((name, None)); continue; }
            let kind = value.get("type").and_then(Value::as_u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing registry type"))?;
            let bytes: Vec<u8> = serde_json::from_value(value.get("bytes").cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing registry bytes"))?)?;
            restored.push((name, Some(RegValue { vtype: value_type(kind)?, bytes })));
        }
        for (name, value) in restored {
            match value {
                Some(v) => key.set_raw_value(name, &v)?,
                None => match key.delete_value(name) {
                    Ok(()) => (), Err(e) if e.kind() == io::ErrorKind::NotFound => (), Err(e) => return Err(e.into()),
                },
            }
        }
        refresh()
    }

    fn enable(port: &str) -> Result<()> {
        let port: u16 = port.parse()?;
        if port == 0 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "port must be between 1 and 65535").into()); }
        let key = key()?;
        let path = path()?;
        let applied = format!("127.0.0.1:{port}");
        let already_active = path.exists();
        let pac: String = key.get_value("AutoConfigURL").unwrap_or_default();
        let detect: u32 = key.get_value("AutoDetect").unwrap_or(0);
        if !pac.trim().is_empty() || detect != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "PAC or automatic proxy detection is enabled; disable it before enabling the manual proxy").into());
        }
        if !path.exists() {
            let data = serde_json::to_vec(&snapshot(&key, &applied)?)?;
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => { file.write_all(&data)?; file.sync_all()?; },
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
        }
        // Validate the backup before making changes, including on repeated enable.
        let backup: Value = serde_json::from_slice(&fs::read(&path)?)?;
        if backup.get("version").and_then(Value::as_u64) != Some(1) || !backup.get("values").is_some_and(Value::is_object)
            || backup.get("applied_server").and_then(Value::as_str) != Some(applied.as_str()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid proxy backup; refusing to change settings").into());
        }
        if already_active {
            let current: String = key.get_value("ProxyServer").unwrap_or_default();
            let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
            if current != applied || enabled != 1 {
                return Err(io::Error::new(io::ErrorKind::Other, "proxy settings changed since activation; refusing to overwrite them; backup retained").into());
            }
        }
        let apply = (|| -> Result<()> {
            key.set_value("ProxyServer", &applied)?;
            key.set_value("ProxyEnable", &1u32)?;
            refresh()
        })();
        if let Err(e) = apply {
            if let Err(restore_error) = restore(&key, &backup) {
                return Err(io::Error::other(format!("proxy update failed: {e}; restoration failed: {restore_error}; backup retained at {}", path.display())).into());
            }
            return Err(e);
        }
        println!("Windows system proxy enabled at 127.0.0.1:{port}; backup: {}", path.display());
        Ok(())
    }

    fn disable() -> Result<()> {
        let path = path()?;
        let data: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let key = key()?;
        let expected = data.get("applied_server").and_then(Value::as_str)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proxy backup"))?;
        let current: String = key.get_value("ProxyServer").unwrap_or_default();
        let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        let pac: String = key.get_value("AutoConfigURL").unwrap_or_default();
        let detect: u32 = key.get_value("AutoDetect").unwrap_or(0);
        if current != expected || enabled != 1 || !pac.trim().is_empty() || detect != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "proxy settings changed since activation; refusing to overwrite them; backup retained").into());
        }
        restore(&key, &data)?;
        fs::remove_file(&path)?;
        println!("Original Windows system proxy settings restored");
        Ok(())
    }

    pub fn run(args: &[String]) -> Result<()> {
        match args {
            [cmd, port] if cmd == "on" => enable(port),
            [cmd] if cmd == "off" => disable(),
            [cmd] if cmd == "status" => {
                let key = key()?;
                let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
                let server: String = key.get_value("ProxyServer").unwrap_or_default();
                println!("enabled={}; server={}; backup_exists={}", enabled != 0, server, path()?.exists());
                Ok(())
            },
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: system-proxy on <HTTP port> | off | status").into()),
        }
    }
}

#[cfg(windows)]
pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> { windows::run(args) }
