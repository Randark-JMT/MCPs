# DoH MCP Server

基于 Cloudflare Workers 的 DNS over HTTPS (DoH) 服务器，集成 Model Context Protocol (MCP) 支持，为 AI 模型提供 DNS 查询功能。

## 🌟 功能特性

- **并行 DNS 查询**: 同时查询多个公共 DoH 服务器获取最快可靠的结果
- **智能共识算法**: 自动选择最具共识性的 DNS 解析结果
- **完整 MCP 支持**: 标准化的工具和资源接口
- **Web 可视化界面**: 美观的前端查询面板，支持实时调试
- **多种记录类型**: 支持 A、AAAA、CNAME、MX、TXT、NS、PTR、SRV、SOA 记录
- **调试功能**: 详细的多服务器响应分析
- **REST API**: 提供标准 HTTP API 接口
- **高性能**: 基于 Cloudflare Workers 的边缘计算
- **TypeScript 开发**: 完整的类型安全和现代化架构

## 🚀 快速部署

### 一键部署

[![Deploy to Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Randark-JMT/MCPs/tree/main/doh-worker)

### 命令行部署

```bash
npm create cloudflare@latest -- my-doh-server --template=https://github.com/Randark-JMT/MCPs/tree/main/doh-worker
```

### 本地开发

```bash
# 克隆项目
git clone https://github.com/Randark-JMT/MCPs.git
cd MCPs/doh-worker

# 安装依赖
npm install

# 本地开发
npm run dev

# 部署到生产环境
npm run deploy
```

## 🔧 MCP 工具

### 1. dns_lookup

执行域名的 DNS 查询，返回最佳结果。

```typescript
{
  domain: string,        // 要查询的域名
  type?: DNSRecordType,  // DNS 记录类型 (默认: "A")
  timeout?: number       // 超时时间，毫秒 (默认: 500)
}
```

**示例用法**:
- `dns_lookup({"domain": "google.com"})`
- `dns_lookup({"domain": "example.com", "type": "MX"})`
- `dns_lookup({"domain": "cloudflare.com", "type": "AAAA", "timeout": 1000})`

### 2. dns_debug

获取多个 DoH 服务器的详细调试信息，用于故障排查。

```typescript
{
  domain: string,        // 要调试的域名
  type?: DNSRecordType,  // DNS 记录类型 (默认: "A")
  timeout?: number       // 超时时间，毫秒 (默认: 2000)
}
```

**示例用法**:
- `dns_debug({"domain": "problematic-domain.com"})`
- `dns_debug({"domain": "example.com", "type": "TXT", "timeout": 5000})`

### 3. get_doh_servers

获取所有可用的 DoH 服务器列表。

```typescript
{}  // 无需参数
```

### 4. dns_record_types

获取支持的 DNS 记录类型说明。

```typescript
{}  // 无需参数
```

## 🌐 支持的 DoH 服务器

- **DNSPod**: `https://doh.pub/dns-query`
- **Alidns**: `https://dns.alidns.com/dns-query`
- **360**: `https://doh.360.cn`
- **Google**: `https://dns.google/dns-query`
- **Cloudflare**: `https://cloudflare-dns.com/dns-query`
- **Quad9**: `https://dns.quad9.net/dns-query`
- **DNS.SB**: `https://doh.dns.sb/dns-query`
- **OpenDNS**: `https://doh.opendns.com/dns-query`
- **AdGuard**: `https://dns.adguard-dns.com/dns-query`

## 📊 支持的 DNS 记录类型

| 类型 | 说明 | 用途 |
|------|------|------|
| A | IPv4 地址记录 | 域名到 IPv4 地址映射 |
| AAAA | IPv6 地址记录 | 域名到 IPv6 地址映射 |
| CNAME | 别名记录 | 域名别名 |
| MX | 邮件交换记录 | 邮件服务器配置 |
| TXT | 文本记录 | SPF、DKIM、验证等 |
| NS | 名称服务器记录 | 域名服务器信息 |
| PTR | 反向 DNS 记录 | IP 地址到域名映射 |
| SRV | 服务记录 | 服务发现 |
| SOA | 授权开始记录 | 域管理信息 |

## 🔌 连接方式

### Cloudflare AI Playground

1. 访问 https://playground.ai.cloudflare.com/
2. 输入您的 MCP 服务器 URL: `your-doh-server.your-account.workers.dev/sse`
3. 开始使用 DNS 查询工具！

### Claude Desktop

在 Claude Desktop 设置中添加配置：

```json
{
  "mcpServers": {
    "doh-server": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-doh-server.your-account.workers.dev/sse"
      ]
    }
  }
}
```

### 其他 MCP 客户端

支持标准 MCP 协议的任何客户端都可以连接：

- **SSE 端点**: `/sse`
- **HTTP 端点**: `/mcp`

## 🛠️ API 端点

### Web 界面
- `GET /` - 主页面（Web 查询界面）
- `GET /debug` - 调试页面（同主页面）

### MCP 协议端点
- `POST /sse` - MCP SSE 连接
- `GET /sse` - MCP SSE 初始化
- `POST /mcp` - MCP HTTP 协议

### REST API 端点
- `POST /api/dns/lookup` - DNS 查询 API
- `POST /api/dns/debug` - DNS 调试 API

### 传统端点
- `GET /dns-query` - 传统 DoH 查询接口（兼容性）

### REST API 使用示例

#### DNS 查询 API
```bash
curl -X POST https://your-worker.workers.dev/api/dns/lookup \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com", "type": "A", "timeout": 1000}'
```

#### DNS 调试 API  
```bash
curl -X POST https://your-worker.workers.dev/api/dns/debug \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com", "type": "A", "timeout": 2000}'
```

## 🏗️ 架构特点

### 智能共识算法
- 并行查询多个 DoH 服务器
- 统计答案一致性
- 选择共识度最高的结果
- 优选响应时间最快的服务器

### 容错机制
- 500ms 默认超时保护
- 自动跳过失败的服务器
- 详细的错误信息记录
- 优雅的降级处理

### 现代化开发
- TypeScript 完整类型支持
- Biome 代码格式化和检查
- Cloudflare Workers 边缘计算
- 标准 MCP 协议实现

## 🔧 配置选项

### 超时时间建议
- **快速查询**: 100-500ms
- **标准查询**: 500-1000ms  
- **调试模式**: 2000-5000ms
- **网络不佳**: 5000-10000ms

### 性能优化
- 使用较短超时时间提高响应速度
- 调试模式使用较长超时获取完整信息
- 根据网络环境调整超时参数

## 📝 开发说明

### 项目结构
```
doh-worker/
├── src/
│   └── index.ts              # 主要业务逻辑
├── package.json              # 项目依赖
├── wrangler.jsonc           # Cloudflare Workers 配置
├── tsconfig.json            # TypeScript 配置
├── biome.json              # 代码格式化配置
├── worker-configuration.d.ts # 类型定义
└── README.md               # 项目文档
```

### 添加新的 DNS 工具
1. 在 `DoHMCP` 类的 `init()` 方法中添加新工具
2. 使用 `this.server.tool()` 定义工具
3. 使用 Zod 定义参数验证schema
4. 实现异步处理函数

### 添加新的 DoH 服务器
1. 在 `DOH_SERVERS` 对象中添加新服务器
2. 确保服务器支持标准 DoH 协议
3. 测试服务器的可用性和响应时间

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 🔗 相关链接

- [Model Context Protocol 文档](https://modelcontextprotocol.io/)
- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [DNS over HTTPS 规范](https://tools.ietf.org/html/rfc8484)
- [项目仓库](https://github.com/Randark-JMT/MCPs)
