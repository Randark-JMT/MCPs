# DoH MCP Server 部署指南

## 📋 部署前准备

### 1. 环境要求
- Node.js 18+ 
- npm 或 yarn
- Cloudflare 账户
- Wrangler CLI

### 2. 安装依赖
```bash
cd doh-worker
npm install
```

### 3. 登录 Cloudflare
```bash
npx wrangler auth login
```

## 🚀 部署步骤

### 方式一：直接部署
```bash
npm run deploy
```

### 方式二：自定义配置
1. 修改 `wrangler.jsonc` 中的 `name` 字段
2. 运行部署命令：
```bash
npx wrangler deploy
```

### 方式三：预览部署
```bash
npx wrangler deploy --dry-run
```

## 🔧 配置选项

### 自定义域名
在 `wrangler.jsonc` 中添加：
```jsonc
{
  "routes": [
    {
      "pattern": "yourdomain.com/*",
      "custom_domain": true
    }
  ]
}
```

### 环境变量
在 `wrangler.jsonc` 中添加：
```jsonc
{
  "vars": {
    "ENVIRONMENT": "production",
    "LOG_LEVEL": "info"
  }
}
```

### KV 存储（可选）
```jsonc
{
  "kv_namespaces": [
    {
      "binding": "CACHE",
      "id": "your-kv-namespace-id"
    }
  ]
}
```

## 📊 监控和日志

### 实时日志
```bash
npx wrangler tail
```

### 过滤日志
```bash
npx wrangler tail --format=pretty --status=error
```

### 性能监控
- 访问 Cloudflare Dashboard
- 进入 Workers & Pages → Analytics

## 🧪 测试部署

### 1. 基本连通性
```bash
curl https://your-worker.your-account.workers.dev/
```

### 2. DNS 查询测试
```bash
curl -X POST https://your-worker.your-account.workers.dev/api/dns/lookup \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com", "type": "A"}'
```

### 3. MCP 连接测试
```bash
curl https://your-worker.your-account.workers.dev/mcp
```

## 🔄 更新部署

### 代码更新
```bash
git pull origin main
npm run deploy
```

### 版本回滚
```bash
npx wrangler rollback --name your-worker-name
```

## ⚠️ 故障排查

### 常见问题

#### 1. 部署失败
- 检查 `wrangler.jsonc` 语法
- 确认登录状态：`npx wrangler whoami`
- 检查账户权限

#### 2. Assets 无法加载
- 确认 `static` 目录存在
- 检查 `wrangler.jsonc` 中的 assets 配置
- 验证文件路径

#### 3. MCP 连接错误
- 检查 Durable Objects 配置
- 确认 bindings 正确
- 查看 Worker 日志

#### 4. DNS 查询超时
- 调整超时参数
- 检查网络连接
- 查看错误日志

### 调试命令
```bash
# 本地开发
npm run dev

# 类型检查
npm run type-check

# 代码格式化
npm run format

# 代码检查
npm run lint:fix
```

## 📈 性能优化

### 1. 缓存策略
```typescript
// 在 Worker 中添加缓存
const cache = caches.default;
const cacheKey = new Request(url, request);
let response = await cache.match(cacheKey);
```

### 2. 请求限制
```typescript
// 限制并发请求
const MAX_CONCURRENT = 5;
```

### 3. 超时优化
```typescript
// 根据用户位置调整超时
const timeout = userRegion === 'CN' ? 1000 : 500;
```

## 🔒 安全配置

### 1. CORS 策略
```typescript
const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://yourdomain.com',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
```

### 2. 速率限制
```typescript
// 使用 KV 实现速率限制
const rateLimitKey = `rate_limit:${clientIP}`;
```

### 3. 输入验证
```typescript
// 严格验证输入参数
if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
  throw new Error('Invalid domain');
}
```

## 📞 技术支持

### 官方文档
- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Wrangler CLI 文档](https://developers.cloudflare.com/workers/wrangler/)
- [MCP 协议文档](https://modelcontextprotocol.io/)

### 社区资源
- [Cloudflare Discord](https://discord.gg/cloudflaredev)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/cloudflare-workers)
- [项目 Issues](https://github.com/Randark-JMT/MCPs/issues)

### 问题报告
如遇到问题，请提供：
1. 错误信息和日志
2. 部署配置文件
3. 复现步骤
4. 环境信息
