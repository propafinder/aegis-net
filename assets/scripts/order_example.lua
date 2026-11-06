-- Пример для direct.lua_order_script / lua_chunk_script (cargo build -p aegis-client --features lua)
-- Переупорядочивание стратегий после Brain (nil = не менять).
function order(preferred, ip_ver)
  return nil
end

-- Правка первого TCP/TLS буфера после встроенных tls_grease / SNI (nil = не менять).
function mutate_chunk(data, ip_ver)
  return nil
end
