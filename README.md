# cf-trojan-vless

## 项目简介/用途
`cf-trojan-vless` 是一个基于 Cloudflare Workers 的轻量级 Trojan/VLESS 代理转发服务脚本，可用于实现安全代理流量转发，适合自建科学上网节点。支持 WebSocket 传输，密码加密校验，适合部署于 Cloudflare Edge 实现免服务器代理。

## 功能列表
- 支持 Trojan/VLESS 协议流量转发
- 密码加密校验（SHA224）
- 多端口/多 IP 随机分配
- 支持 WebSocket 通讯
- 反向代理 HTTP 路径
- 可扩展配置自定义 UUID、IP 列表、子路径等
- 环境变量设置进行参数管理

## 安装与使用方法
1. **部署到 Cloudflare Workers：**
   - 复制本仓库中的 `trojan.js` 或 `worker-vless.js` 脚本到 Cloudflare Workers 编辑器。
   - 设置环境变量（如 `PSWD`）用于连接验证。

2. **本地配置客户端：**
   - 使用 Trojan/VLESS 客户端，填写 Cloudflare Workers 地址、端口以及密码（与环境变量一致）。
   - 示例 Trojan 格式（unicode）：
     ```
     trojan://${PSWD}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}
     ```

3. **启动代理服务：**
   - 访问 Cloudflare Workers 地址即可自动进行流量转发。
   - 支持通过 WebSocket 协议连接，确保客户端配置一致。

## 配置说明
- **环境变量：**
  - `PSWD`：代理连接密码
  - `pip`/`ips`：后端转发 IP 列表
  - `cdnip`/`pxyIP`：CDN 中转域名或 IP
  - `iduu`：VLESS 协议 UUID
  - `subpath`：自定义路径
- 可根据需求在脚本顶部进行修改，或通过 Cloudflare Workers 环境变量管理界面配置。

## 依赖环境
- Cloudflare Workers 平台
- JavaScript（无需额外依赖包，已内置 SHA224 加密）
- Trojan/VLESS 客户端工具（如 Clash、V2Ray、Trojan-Qt5）

## 联系方式/贡献方式
- 作者 GitHub: [ycm50](https://github.com/ycm50)
- 欢迎 issue/PR 交流反馈，完善功能
- 贡献方式：fork 本仓库，提交 PR 或补充文档、代码优化

---
如需更多功能或定制化支持，欢迎通过 GitHub Issue 联系交流。
