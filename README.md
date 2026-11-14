# RustProxy

RustProxy 是 Rust 编写的 Windows 命令行配置管理器，VLESS、XTLS-Vision、REALITY、SOCKS5、HTTP 和转发由独立的官方 Xray-core 进程实现；它不是纯 Rust 的协议实现。构建包固定使用 Xray-core v26.11.9。请遵守当地法律与网络使用规定。

## 准备

安装 Rust 和 Windows MSVC C++ 构建工具，执行 `cargo build --release --target x86_64-pc-windows-msvc`。将官方 `xray.exe` 放在两个程序旁，或者将环境变量 `XRAY_BIN` 设置为其绝对路径。运行时需要同目录的 Xray 附带资源（例如 geosite、geoip）时，请保留它们。发布版 Xray 文件采用官方发布页的 SHA-256 校验，具体见 发行包中的 `SHA256SUMS.txt`。

## 配置与启动

1. 在可信设备运行 `server.exe keygen`。输出中的 PrivateKey 仅放在服务端，Password (PublicKey) 填入客户端的 public_key。UUID、ShortId 填入双方对应字段。密钥和 UUID 应保密，不要提交到 Git 或发送给不可信的人。
2. 复制 `examples/server_config.json` 与 `examples/client_config.json`，替换占位值。JSON 不允许注释，以下说明各字段。
3. 服务端运行 `server.exe run server_config.json`。客户端运行 `client.exe check client_config.json` 验证配置，再运行 `client.exe run client_config.json`。
4. 应用可连接本机 SOCKS5 `127.0.0.1:1080` 或 HTTP `127.0.0.1:1081`。示例端口可改。`client.exe tcp-ping client_config.json` 只测 TCP 连接，不代表认证或代理可用。通过代理访问可信 HTTPS 网站才能验证完整链路，例如 `curl.exe --proxy http://127.0.0.1:1081 https://example.com/`。

服务端字段：`listen`/`port` 为监听地址及端口；`clients` 为允许的 UUID 列表；`dest` 为 Reality 回退目标和端口；`server_names` 是允许的 TLS SNI 列表；`private_key` 和 `short_ids` 分别为私钥和十六进制短 ID 列表。客户端 `server_address`/`server_port` 指向服务端，`uuid`、`short_id` 须对应服务端；`public_key` 是服务端私钥对应的公钥；`server_name` 必须是允许的 SNI；`socks_port` 和 `http_port` 为本机端口。选择受控且可用的 TLS 1.3 目标，防火墙应允许服务端监听端口。

配置保存在普通 JSON 文件中，没有静态加密；请通过文件系统权限保护私钥和客户端凭据。程序通过标准输入将生成的配置交给 Xray，不创建额外配置文件。认证失败的连接按 Xray Reality 的行为转发给目标，不能保证返回 HTTP 200；应防范回退目标造成开放转发滥用，并遵循 Xray 官方更新和安全公告。UDP 支持取决于 Xray 的协议和应用；HTTP 代理本身不提供通用 UDP 隧道。停止前台进程使用 Ctrl+C。

更多协议说明参见 [Xray Reality 文档](https://xtls.github.io/en/config/transports/reality.html) 和 [官方示例](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision-REALITY)。

## 配置档案与 Windows 系统代理

`client.exe import <源文件> <档案目录> <名称>` 导入；`list <档案目录>` 列出；`export <档案目录> <名称> <目标文件>` 导出；`delete <档案目录> <名称>` 删除。编辑可导出为新文件、修改后以新名称导入。导入和导出不会覆盖已有文件。

客户端运行时可使用 `client.exe system-proxy on 1081` 启用当前 Windows 用户的手动 HTTP 代理；`system-proxy status` 查看状态，`system-proxy off` 恢复原设置。启用前会在本地用户目录备份，关闭客户端不会自动恢复，请手动执行 off。若检测到 PAC 或自动发现设置，或代理设置在启用后被其他程序改变，程序会拒绝覆盖；部分连接专属 WPAD 设置可能无法检测。系统代理主要影响遵循 Windows 代理设置的应用，不是 VPN，也不一定接管所有流量。

运行客户端后，`client.exe reality-test 1081 https://example.com/` 使用系统的 curl 通过本地 HTTP 代理执行 HTTPS 请求并报告耗时，可验证实际连接；它需要该目标网站可用，也不代表全部应用的连接都正常。


## 图形向导与系统托盘（Windows）

双击 `server-gui.exe`，首次运行会打开配置向导。填写客户端可访问的服务器公网 IP 或域名，确认 Reality 目标站；默认只允许本机连接，如需让其他设备连接，请勾选外部监听。向导生成服务端私钥和认证信息、选择当时空闲的端口，并生成独立的客户端连接文件。用安全渠道把客户端文件交给客户端，绝不要分享服务端私钥；外网使用还需要相应防火墙和路由器端口设置。端口探测后可能被其他进程抢占，启动失败时请重新配置或检查占用。

双击 `client-gui.exe`，在向导中导入服务端生成的客户端文件并保存到当前用户目录。导入时程序选择本机空闲的 SOCKS5 和 HTTP 端口。托盘图标右键菜单提供配置向导、选择或编辑配置、启动、停止和状态；客户端还可以主动启用或恢复 Windows 系统代理。托盘程序正常停止、退出或发现客户端意外退出时会尝试恢复由它启用的系统代理。如果托盘被强制结束或系统崩溃，可以重新打开托盘并选择“恢复 Windows 系统代理”，或运行 `client.exe system-proxy off`。其他程序修改了代理设置时，恢复会拒绝覆盖并保留备份。

向导生成的文件含明文凭据，目录权限继承系统 ACL；请确保其他不可信用户不能读取，避免将配置放在共享目录或上传公开仓库。客户端文件包含认证信息，泄露后应更换服务端认证 UUID 和客户端配置。系统代理只影响使用 Windows 代理设置的应用；特殊的 PAC/WPAD 或连接专属设置可能影响效果。托盘运行时必须保留程序和 Xray 文件在同一目录；修改配置后需要停止并重新启动才能生效。

命令行仍可使用。自动生成的接口是 `server.exe setup <目录> <服务器地址> <SNI> <目标:端口> <监听IP>`，例如监听 IP 使用 `127.0.0.1` 进行本机测试；客户端自动导入是 `client.exe import-auto <源JSON> <新JSON>`，均不覆盖已有文件。

托盘会记住最后使用的配置文件路径，下次打开图形程序时自动尝试启动；系统代理仍需手动启用。
