//! Lua-хуки (feature `lua`): `order`, `mutate_chunk` — переупорядочивание стратегий и правка первого буфера.

#[cfg(feature = "lua")]
fn apply_order_hook_from_file(
    path: &std::path::Path,
    preferred: &[String],
    ip_ver: u8,
) -> Result<Option<Vec<String>>, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("read lua: {e}"))?;
    let lua = mlua::Lua::new();
    lua.load(&src)
        .exec()
        .map_err(|e| format!("lua load: {e}"))?;
    let globals = lua.globals();
    let order_fn: Option<mlua::Function> = globals.get("order").ok();
    let Some(order_fn) = order_fn else {
        return Ok(None);
    };
    let pref = lua.create_table().map_err(|e| e.to_string())?;
    for (i, s) in preferred.iter().enumerate() {
        pref.raw_set(i + 1, s.as_str()).map_err(|e| e.to_string())?;
    }
    let ret = order_fn
        .call::<(mlua::Table, u8), mlua::Value>((pref, ip_ver))
        .map_err(|e| format!("lua order(): {e}"))?;
    match ret {
        mlua::Value::Nil => Ok(None),
        mlua::Value::Table(t) => {
            let n = t.len().map_err(|e| e.to_string())? as usize;
            if n == 0 {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(n);
            for i in 1..=n {
                let s: String = t.get(i).map_err(|e| e.to_string())?;
                out.push(s);
            }
            Ok(Some(out))
        }
        _ => Err("order() must return nil or array table".into()),
    }
}

#[cfg(feature = "lua")]
fn apply_chunk_hook_from_file(
    path: &std::path::Path,
    buf: &[u8],
    ip_ver: u8,
) -> Result<Option<Vec<u8>>, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("read lua: {e}"))?;
    let lua = mlua::Lua::new();
    lua.load(&src)
        .exec()
        .map_err(|e| format!("lua load: {e}"))?;
    let globals = lua.globals();
    let f: Option<mlua::Function> = globals.get("mutate_chunk").ok();
    let Some(f) = f else {
        return Ok(None);
    };
    let s = lua.create_string(buf).map_err(|e| e.to_string())?;
    let ret = f
        .call::<(mlua::String, u8), mlua::Value>((s, ip_ver))
        .map_err(|e| format!("lua mutate_chunk(): {e}"))?;
    match ret {
        mlua::Value::Nil => Ok(None),
        mlua::Value::String(out) => Ok(Some(out.as_bytes().to_vec())),
        _ => Err("mutate_chunk must return string or nil".into()),
    }
}

/// Если путь задан и сборка с `--features lua`, вызывает скрипт; иначе `Ok(None)`.
pub fn try_apply_order_hook(
    path: Option<&std::path::Path>,
    preferred: &[String],
    ip_ver: u8,
) -> Result<Option<Vec<String>>, String> {
    #[cfg(feature = "lua")]
    {
        let Some(p) = path else {
            return Ok(None);
        };
        apply_order_hook_from_file(p, preferred, ip_ver)
    }
    #[cfg(not(feature = "lua"))]
    {
        let _ = (path, preferred, ip_ver);
        Ok(None)
    }
}

/// Модификация первого чанка: глобальная `mutate_chunk(data, ip_ver)` → строка байт или `nil`.
pub fn try_apply_chunk_hook(
    path: Option<&std::path::Path>,
    buf: &[u8],
    ip_ver: u8,
) -> Result<Option<Vec<u8>>, String> {
    #[cfg(feature = "lua")]
    {
        let Some(p) = path else {
            return Ok(None);
        };
        apply_chunk_hook_from_file(p, buf, ip_ver)
    }
    #[cfg(not(feature = "lua"))]
    {
        let _ = (path, buf, ip_ver);
        Ok(None)
    }
}

#[cfg(feature = "lua")]
pub fn eval_strategy_hook(lua_src: &str) -> std::result::Result<(), mlua::Error> {
    let lua = mlua::Lua::new();
    lua.load(lua_src).exec()?;
    Ok(())
}

#[cfg(not(feature = "lua"))]
pub fn eval_strategy_hook(_lua_src: &str) -> std::result::Result<(), &'static str> {
    Err("build without `--features lua`")
}

pub const LUA_ENGINE_ABI: &str = "aegis-lua-0.3-chunk-hook";
