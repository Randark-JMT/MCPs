/**
 * Cloudflare Worker DoH (DNS over HTTPS) Service + MCP Server
 * 
 * 这个Worker实现了一个DoH服务，支持：
 * - 并行查询多个公共DoH服务器
 * - 500ms超时保护
 * - 返回最快的可靠结果
 * - 支持标准的DoH查询格式
 * - 支持MCP (Model Context Protocol) 协议
 */

// MCP服务器信息
const MCP_SERVER_INFO = {
    name: "doh-mcp-server",
    version: "1.0.0",
    description: "DNS over HTTPS service with MCP support for AI models",
    capabilities: {
        tools: {},
        resources: {},
        prompts: {},
        experimental: {
            streamableHttp: true
        }
    }
};

// MCP工具定义
const MCP_TOOLS = {
    "dns_lookup": {
        name: "dns_lookup",
        description: "执行域名的DNS查询，支持指定记录类型。通过并行查询多个公共DoH服务器获取最快的可靠结果。适用于：域名解析验证、IP地址查询、邮件服务器配置检查、DNS记录验证等场景。返回共识度最高的DNS记录结果。",
        inputSchema: {
            type: "object",
            properties: {
                domain: {
                    type: "string",
                    description: "要查询的域名，例如：google.com, example.org, mail.domain.com。支持国际化域名(IDN)和各级子域名。"
                },
                type: {
                    type: "string",
                    enum: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "SOA"],
                    description: "DNS记录类型。A: IPv4地址记录；AAAA: IPv6地址记录；CNAME: 别名记录；MX: 邮件交换记录；TXT: 文本记录(SPF/DKIM等)；NS: 名称服务器记录；PTR: 反向DNS查询(IP转域名)；SRV: 服务记录；SOA: 授权开始记录(域管理信息)。",
                    default: "A"
                },
                timeout: {
                    type: "number",
                    description: "查询超时时间（毫秒）。较短超时(100-500ms)适合快速查询，较长超时(1000-5000ms)适合网络条件不佳时使用。默认500ms平衡速度与成功率。",
                    default: 500,
                    minimum: 100,
                    maximum: 10000
                }
            },
            required: ["domain"]
        }
    },
    "dns_debug": {
        name: "dns_debug",
        description: "获取多个DoH服务器的详细DNS调试信息，用于诊断DNS解析问题和分析不同服务器的响应差异。返回每个服务器的详细响应时间、解析结果、错误信息等。适用于：DNS故障排查、服务器性能对比、解析一致性检查、网络连通性测试等场景。",
        inputSchema: {
            type: "object",
            properties: {
                domain: {
                    type: "string",
                    description: "要调试的域名，建议使用存在解析问题或需要详细分析的域名。支持测试各种域名格式和特殊情况。"
                },
                type: {
                    type: "string",
                    enum: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "SOA"],
                    description: "要调试的DNS记录类型。不同类型记录可能在不同服务器上表现不同，选择合适的类型有助于精确定位问题。常用A记录测试基本连通性，MX记录测试邮件配置。",
                    default: "A"
                },
                timeout: {
                    type: "number",
                    description: "调试查询的超时时间（毫秒）。调试模式建议使用较长超时时间(2000-5000ms)以获取更完整的服务器响应信息，便于分析慢响应服务器的问题。",
                    default: 2000,
                    minimum: 100,
                    maximum: 10000
                }
            },
            required: ["domain"]
        }
    }
};

// MCP资源定义
const MCP_RESOURCES = {
    "doh_servers": {
        uri: "doh://servers/list",
        name: "DoH Servers List",
        description: "List of available DNS over HTTPS servers",
        mimeType: "application/json"
    },
    "dns_types": {
        uri: "dns://types/supported",
        name: "Supported DNS Types",
        description: "List of supported DNS record types",
        mimeType: "application/json"
    }
};

// 公共DoH服务器列表
const DOH_SERVERS = {
    "DNSPod": "https://doh.pub/dns-query",
    "Alidns": "https://dns.alidns.com/dns-query",
    "360": "https://doh.360.cn",
    "Google": "https://dns.google/dns-query",
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Quad9": "https://dns.quad9.net/dns-query",
    "DNS.SB": "https://doh.dns.sb/dns-query",
    "OpenDNS": "https://doh.opendns.com/dns-query",
    // "Yandex": "https://common.dot.dns.yandex.net/dns-query",
    "AdGuard": "https://dns.adguard-dns.com/dns-query"
};

// DNS记录类型映射
const DNS_TYPES = {
    'A': 1,
    'AAAA': 28,
    'CNAME': 5,
    'MX': 15,
    'TXT': 16,
    'NS': 2,
    'PTR': 12,
    'SRV': 33,
    'SOA': 6
};

// 将域名转换为DNS查询格式
function encodeDomainName(domain) {
    const parts = domain.split('.');
    let encoded = '';

    for (const part of parts) {
        if (part.length > 0) {
            encoded += String.fromCharCode(part.length) + part;
        }
    }

    encoded += '\0'; // 结束符
    return encoded;
}

// 解析DNS响应中的域名
function parseDomainName(buffer, offset) {
    const view = new DataView(buffer);
    const labels = [];
    let currentOffset = offset;
    let jumped = false;
    let maxJumps = 10; // 防止无限循环

    while (currentOffset < buffer.byteLength && maxJumps > 0) {
        const len = view.getUint8(currentOffset);

        if (len === 0) {
            // 域名结束
            break;
        } else if ((len & 0xC0) === 0xC0) {
            // 压缩指针
            if (!jumped) {
                // 只在第一次跳转时记录位置
            }
            const pointer = ((len & 0x3F) << 8) | view.getUint8(currentOffset + 1);
            currentOffset = pointer;
            jumped = true;
            maxJumps--;
        } else {
            // 普通标签
            currentOffset++;
            if (currentOffset + len <= buffer.byteLength) {
                const label = new Uint8Array(buffer, currentOffset, len);
                labels.push(String.fromCharCode(...label));
                currentOffset += len;
            } else {
                break;
            }
        }
    }

    return labels.join('.');
}

// 跳过DNS响应中的域名，返回域名后的偏移量
function skipDomainName(buffer, offset) {
    const view = new DataView(buffer);
    let currentOffset = offset;

    while (currentOffset < buffer.byteLength) {
        const len = view.getUint8(currentOffset);

        if (len === 0) {
            return currentOffset + 1;
        } else if ((len & 0xC0) === 0xC0) {
            return currentOffset + 2;
        } else {
            currentOffset += len + 1;
        }
    }

    return currentOffset;
}

// 构建DNS查询包
function buildDNSQuery(domain, type = 'A') {
    const typeCode = DNS_TYPES[type] || 1;

    // DNS头部 (12字节)
    const id = Math.floor(Math.random() * 65536);
    const flags = 0x0100; // 标准查询，期望递归
    const qdcount = 1;    // 问题数量
    const ancount = 0;    // 答案数量
    const nscount = 0;    // 权威记录数量
    const arcount = 0;    // 附加记录数量

    const header = new ArrayBuffer(12);
    const view = new DataView(header);

    view.setUint16(0, id);
    view.setUint16(2, flags);
    view.setUint16(4, qdcount);
    view.setUint16(6, ancount);
    view.setUint16(8, nscount);
    view.setUint16(10, arcount);

    // 问题部分
    const encodedDomain = encodeDomainName(domain);
    const question = new ArrayBuffer(encodedDomain.length + 4);
    const questionView = new Uint8Array(question);

    // 写入编码后的域名
    for (let i = 0; i < encodedDomain.length; i++) {
        questionView[i] = encodedDomain.charCodeAt(i);
    }

    // 写入查询类型和类别
    const questionDataView = new DataView(question);
    questionDataView.setUint16(encodedDomain.length, typeCode);     // QTYPE
    questionDataView.setUint16(encodedDomain.length + 2, 1);        // QCLASS (IN)

    // 合并头部和问题
    const query = new Uint8Array(header.byteLength + question.byteLength);
    query.set(new Uint8Array(header), 0);
    query.set(new Uint8Array(question), header.byteLength);

    return query;
}

// 解析DNS响应
function parseDNSResponse(response) {
    const view = new DataView(response);

    if (response.byteLength < 12) {
        throw new Error('响应太短');
    }

    const id = view.getUint16(0);
    const flags = view.getUint16(2);
    const qdcount = view.getUint16(4);
    const ancount = view.getUint16(6);

    // 检查响应码
    const rcode = flags & 0x000F;
    if (rcode !== 0) {
        throw new Error(`DNS错误码: ${rcode}`);
    }

    if (ancount === 0) {
        return { answers: [] };
    }

    // 跳过问题部分 (简化处理)
    let offset = 12;

    // 跳过问题记录
    for (let i = 0; i < qdcount; i++) {
        // 跳过域名部分
        while (offset < response.byteLength) {
            const len = view.getUint8(offset);
            if (len === 0) {
                offset++;
                break;
            }
            if ((len & 0xC0) === 0xC0) {
                offset += 2;
                break;
            }
            offset += len + 1;
        }
        offset += 4; // 跳过QTYPE和QCLASS
    }

    const answers = [];

    // 解析答案记录
    for (let i = 0; i < ancount && offset < response.byteLength; i++) {
        try {
            // 跳过名称部分
            if ((view.getUint8(offset) & 0xC0) === 0xC0) {
                offset += 2;
            } else {
                while (offset < response.byteLength) {
                    const len = view.getUint8(offset);
                    if (len === 0) {
                        offset++;
                        break;
                    }
                    offset += len + 1;
                }
            }

            if (offset + 10 > response.byteLength) break;

            const type = view.getUint16(offset);
            const cls = view.getUint16(offset + 2);
            const ttl = view.getUint32(offset + 4);
            const rdlength = view.getUint16(offset + 8);

            offset += 10;

            if (offset + rdlength > response.byteLength) break;

            let data = '';
            if (type === 1 && rdlength === 4) { // A记录
                const ip = new Uint8Array(response, offset, 4);
                data = Array.from(ip).join('.');
            } else if (type === 28 && rdlength === 16) { // AAAA记录
                const ip6 = new Uint8Array(response, offset, 16);
                const parts = [];
                for (let j = 0; j < 16; j += 2) {
                    parts.push(((ip6[j] << 8) | ip6[j + 1]).toString(16));
                }
                data = parts.join(':').replace(/(:0)+:/g, '::');
            } else if (type === 15) { // MX记录
                const priority = view.getUint16(offset);
                let nameOffset = offset + 2;
                const domainName = parseDomainName(response, nameOffset);
                data = `${priority} ${domainName}`;
            } else if (type === 5) { // CNAME记录
                data = parseDomainName(response, offset);
            } else if (type === 2) { // NS记录
                data = parseDomainName(response, offset);
            } else if (type === 12) { // PTR记录
                data = parseDomainName(response, offset);
            } else if (type === 16) { // TXT记录
                let txtOffset = offset;
                const txtParts = [];
                while (txtOffset < offset + rdlength) {
                    const txtLen = view.getUint8(txtOffset);
                    txtOffset++;
                    if (txtLen > 0 && txtOffset + txtLen <= offset + rdlength) {
                        const txtData = new Uint8Array(response, txtOffset, txtLen);
                        txtParts.push(String.fromCharCode(...txtData));
                        txtOffset += txtLen;
                    } else {
                        break;
                    }
                }
                data = txtParts.join('');
            } else if (type === 33) { // SRV记录
                const priority = view.getUint16(offset);
                const weight = view.getUint16(offset + 2);
                const port = view.getUint16(offset + 4);
                const target = parseDomainName(response, offset + 6);
                data = `${priority} ${weight} ${port} ${target}`;
            } else if (type === 6) { // SOA记录
                let soaOffset = offset;
                const mname = parseDomainName(response, soaOffset);
                // 跳过mname
                soaOffset = skipDomainName(response, soaOffset);
                const rname = parseDomainName(response, soaOffset);
                // 跳过rname
                soaOffset = skipDomainName(response, soaOffset);

                if (soaOffset + 20 <= offset + rdlength) {
                    const serial = view.getUint32(soaOffset);
                    const refresh = view.getUint32(soaOffset + 4);
                    const retry = view.getUint32(soaOffset + 8);
                    const expire = view.getUint32(soaOffset + 12);
                    const minimum = view.getUint32(soaOffset + 16);
                    data = `${mname} ${rname} ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
                }
            }

            if (data) {
                answers.push({
                    type: type,
                    ttl: ttl,
                    data: data
                });
            }

            offset += rdlength;
        } catch (e) {
            break;
        }
    }

    return { answers };
}

// 查询单个DoH服务器
async function queryDoHServer(server, domain, type, timeoutMs) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const dnsQuery = buildDNSQuery(domain, type);

        const response = await fetch(server, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message',
            },
            body: dnsQuery,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const responseBuffer = await response.arrayBuffer();
        const result = parseDNSResponse(responseBuffer);

        return {
            success: true,
            server: server,
            result: result,
            answers: result.answers,
            rawResponse: responseBuffer // 保存原始响应
        };
    } catch (error) {
        clearTimeout(timeoutId);
        return {
            success: false,
            server: server,
            error: error.message
        };
    }
}

// 并行查询多个DoH服务器
async function queryMultipleDoH(domain, type = 'A', timeoutMs = 500) {
    const serverEntries = Object.entries(DOH_SERVERS);
    const promises = serverEntries.map(([name, url]) =>
        queryDoHServer(url, domain, type, timeoutMs).then(result => ({
            ...result,
            serverName: name // 添加服务器名称
        }))
    );

    const results = await Promise.allSettled(promises);

    const successResults = [];
    const failedResults = [];

    results.forEach((result, index) => {
        const [serverName, serverUrl] = serverEntries[index];

        if (result.status === 'fulfilled') {
            if (result.value.success) {
                successResults.push(result.value);
            } else {
                failedResults.push({
                    ...result.value,
                    serverName: serverName
                });
            }
        } else {
            failedResults.push({
                success: false,
                server: serverUrl,
                serverName: serverName,
                error: result.reason?.message || '未知错误'
            });
        }
    });

    return {
        success: successResults,
        failed: failedResults,
        total: Object.keys(DOH_SERVERS).length
    };
}

// 获取最佳结果
function getBestResult(results) {
    if (results.success.length === 0) {
        return null;
    }

    // 统计相同答案的频次
    const answerGroups = new Map();

    results.success.forEach(result => {
        if (result.answers && result.answers.length > 0) {
            const key = result.answers.map(a => a.data).sort().join(',');
            if (!answerGroups.has(key)) {
                answerGroups.set(key, {
                    answers: result.answers,
                    count: 0,
                    servers: [],
                    serverNames: [], // 添加服务器名称列表
                    rawResponse: result.rawResponse // 保存原始DNS响应
                });
            }
            const group = answerGroups.get(key);
            group.count++;
            group.servers.push(result.server);
            group.serverNames.push(result.serverName);
        }
    });

    if (answerGroups.size === 0) {
        return results.success[0];
    }

    // 返回出现次数最多的结果
    let bestGroup = null;
    let maxCount = 0;

    for (const group of answerGroups.values()) {
        if (group.count > maxCount) {
            maxCount = group.count;
            bestGroup = group;
        }
    }

    return bestGroup ? {
        answers: bestGroup.answers,
        consensus: bestGroup.count,
        servers: bestGroup.servers,
        serverNames: bestGroup.serverNames,
        rawResponse: bestGroup.rawResponse
    } : results.success[0];
}

// 构建标准DNS响应包
function buildDNSResponse(domain, type, answers, id = 1234) {
    const typeCode = DNS_TYPES[type] || 1;

    // DNS头部 (12字节)
    const flags = 0x8180; // 响应标志，递归可用，无错误
    const qdcount = 1;    // 问题数量
    const ancount = answers.length; // 答案数量
    const nscount = 0;    // 权威记录数量
    const arcount = 0;    // 附加记录数量

    const header = new ArrayBuffer(12);
    const view = new DataView(header);

    view.setUint16(0, id);
    view.setUint16(2, flags);
    view.setUint16(4, qdcount);
    view.setUint16(6, ancount);
    view.setUint16(8, nscount);
    view.setUint16(10, arcount);

    // 问题部分
    const encodedDomain = encodeDomainName(domain);
    const question = new ArrayBuffer(encodedDomain.length + 4);
    const questionView = new Uint8Array(question);

    // 写入编码后的域名
    for (let i = 0; i < encodedDomain.length; i++) {
        questionView[i] = encodedDomain.charCodeAt(i);
    }

    // 写入查询类型和类别
    const questionDataView = new DataView(question);
    questionDataView.setUint16(encodedDomain.length, typeCode);     // QTYPE
    questionDataView.setUint16(encodedDomain.length + 2, 1);        // QCLASS (IN)

    // 计算答案部分长度
    let answerLength = 0;
    const answerBuffers = [];

    answers.forEach(answer => {
        // 计算数据长度
        let dataLength = 0;
        let answerData = null;

        if (answer.type === 1) { // A记录
            dataLength = 4;
        } else if (answer.type === 28) { // AAAA记录
            dataLength = 16;
        } else if (answer.type === 15) { // MX记录
            const parts = answer.data.split(' ');
            const priority = parseInt(parts[0]);
            const exchange = parts.slice(1).join(' ');
            const encodedExchange = encodeDomainName(exchange);
            dataLength = 2 + encodedExchange.length; // priority(2) + domain
            answerData = { priority, encodedExchange };
        } else if (answer.type === 5 || answer.type === 2 || answer.type === 12) { // CNAME, NS, PTR
            const encodedDomain = encodeDomainName(answer.data);
            dataLength = encodedDomain.length;
            answerData = { encodedDomain };
        } else if (answer.type === 16) { // TXT记录
            const txtData = answer.data;
            dataLength = txtData.length + 1; // 长度字节 + 数据
            answerData = { txtData };
        } else {
            // 跳过不支持的记录类型
            return;
        }

        const answerBuffer = new ArrayBuffer(2 + 2 + 2 + 4 + 2 + dataLength);
        const answerView = new DataView(answerBuffer);
        const answerBytes = new Uint8Array(answerBuffer);

        // 名称压缩指针指向问题中的域名
        answerView.setUint16(0, 0xC00C); // 指向偏移量12（问题开始位置）
        answerView.setUint16(2, answer.type);
        answerView.setUint16(4, 1); // IN类别
        answerView.setUint32(6, answer.ttl);
        answerView.setUint16(10, dataLength);

        // 写入数据
        if (answer.type === 1) { // A记录
            const parts = answer.data.split('.');
            for (let i = 0; i < 4; i++) {
                answerBytes[12 + i] = parseInt(parts[i]);
            }
        } else if (answer.type === 28) { // AAAA记录
            // 简化IPv6处理
            const parts = answer.data.split(':');
            let byteIndex = 12;
            for (const part of parts) {
                if (part === '') continue;
                const value = parseInt(part, 16);
                answerBytes[byteIndex++] = (value >> 8) & 0xFF;
                answerBytes[byteIndex++] = value & 0xFF;
            }
        } else if (answer.type === 15 && answerData) { // MX记录
            answerView.setUint16(12, answerData.priority);
            for (let i = 0; i < answerData.encodedExchange.length; i++) {
                answerBytes[14 + i] = answerData.encodedExchange.charCodeAt(i);
            }
        } else if ((answer.type === 5 || answer.type === 2 || answer.type === 12) && answerData) { // CNAME, NS, PTR
            for (let i = 0; i < answerData.encodedDomain.length; i++) {
                answerBytes[12 + i] = answerData.encodedDomain.charCodeAt(i);
            }
        } else if (answer.type === 16 && answerData) { // TXT记录
            answerBytes[12] = answerData.txtData.length;
            for (let i = 0; i < answerData.txtData.length; i++) {
                answerBytes[13 + i] = answerData.txtData.charCodeAt(i);
            }
        }

        answerBuffers.push(answerBuffer);
        answerLength += answerBuffer.byteLength;
    });

    // 合并所有部分
    const totalLength = header.byteLength + question.byteLength + answerLength;
    const response = new Uint8Array(totalLength);

    let offset = 0;
    response.set(new Uint8Array(header), offset);
    offset += header.byteLength;

    response.set(new Uint8Array(question), offset);
    offset += question.byteLength;

    answerBuffers.forEach(buffer => {
        response.set(new Uint8Array(buffer), offset);
        offset += buffer.byteLength;
    });

    return response.buffer;
}

// MCP 请求处理函数
async function handleMCPRequest(request, url) {
    const method = request.method;
    const pathname = url.pathname;

    // 处理CORS预检请求
    if (method === 'OPTIONS') {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization',
                'Access-Control-Max-Age': '86400',
            }
        });
    }

    try {
        if (method === 'GET') {
            // 处理MCP GET请求
            if (pathname === '/mcp' || pathname === '/mcp/') {
                return handleMCPInfo();
            } else if (pathname === '/mcp/tools') {
                return handleMCPTools();
            } else if (pathname === '/mcp/resources') {
                return handleMCPResources();
            } else if (pathname.startsWith('/mcp/resources/')) {
                const resourceId = pathname.split('/').pop();
                return handleMCPResource(resourceId);
            } else if (pathname === '/mcp/sse') {
                return handleMCPSSE(request);
            } else if (pathname === '/mcp/streamable-http') {
                return handleMCPStreamableHttp(request);
            }
        } else if (method === 'POST') {
            // 处理MCP POST请求
            if (pathname === '/mcp/tools/call') {
                return handleMCPToolCall(request);
            } else if (pathname === '/mcp') {
                // 处理标准 MCP 协议请求
                return handleMCPProtocol(request);
            } else if (pathname === '/mcp/sse') {
                return handleMCPSSEMessage(request);
            } else if (pathname === '/mcp/streamable-http') {
                return handleMCPStreamableHttpMessage(request);
            }
        }

        return new Response(JSON.stringify({
            error: "Not found",
            message: "MCP endpoint not found"
        }), {
            status: 404,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: "Internal server error",
            message: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 处理 MCP SSE 连接
function handleMCPSSE(request) {
    return new Response("", {
        status: 200,
        headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, Cache-Control',
        }
    });
}

// 处理 MCP SSE 消息
async function handleMCPSSEMessage(request) {
    try {
        const data = await request.json();

        // 处理 MCP 协议消息，与 handleMCPProtocol 相同的逻辑
        const result = await processMCPMessage(data);

        return new Response(`data: ${JSON.stringify(result)}\n\n`, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        const errorResponse = {
            jsonrpc: "2.0",
            id: null,
            error: {
                code: -32700,
                message: "Parse error",
                data: error.message
            }
        };

        return new Response(`data: ${JSON.stringify(errorResponse)}\n\n`, {
            status: 400,
            headers: {
                'Content-Type': 'text/event-stream',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 处理 MCP StreamableHttp 连接
function handleMCPStreamableHttp(request) {
    // StreamableHttp 初始化响应
    const initResponse = {
        jsonrpc: "2.0",
        id: null,
        result: {
            protocolVersion: "1.0",
            capabilities: {
                experimental: {
                    streamableHttp: true
                }
            },
            serverInfo: {
                name: MCP_SERVER_INFO.name,
                version: MCP_SERVER_INFO.version
            }
        }
    };

    return new Response(JSON.stringify(initResponse), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
        }
    });
}

// 处理 MCP StreamableHttp 消息
async function handleMCPStreamableHttpMessage(request) {
    try {
        const data = await request.json();

        // 处理 MCP 协议消息，与 handleMCPProtocol 相同的逻辑
        const result = await processMCPMessage(data);

        // StreamableHttp 返回标准JSON响应而不是事件流
        return new Response(JSON.stringify(result), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        const errorResponse = {
            jsonrpc: "2.0",
            id: null,
            error: {
                code: -32700,
                message: "Parse error",
                data: error.message
            }
        };

        return new Response(JSON.stringify(errorResponse), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 处理 MCP 消息的通用函数
async function processMCPMessage(data) {
    const { method, params, id } = data;
    let result = null;
    let error = null;

    switch (method) {
        case 'initialize':
            result = {
                protocolVersion: "2024-11-05",
                capabilities: {
                    tools: {
                        listChanged: false
                    },
                    resources: {
                        subscribe: false,
                        listChanged: false
                    },
                    prompts: {
                        listChanged: false
                    }
                },
                serverInfo: {
                    name: MCP_SERVER_INFO.name,
                    version: MCP_SERVER_INFO.version
                }
            };
            break;

        case 'tools/list':
            result = {
                tools: Object.values(MCP_TOOLS)
            };
            break;

        case 'tools/call':
            const { name: toolName, arguments: toolArgs } = params;
            if (toolName === 'dns_lookup') {
                const lookupResult = await handleDNSLookupTool(toolArgs);
                const lookupData = await lookupResult.json();

                if (lookupData.success) {
                    result = {
                        content: [
                            {
                                type: "text",
                                text: formatDNSResult(lookupData.result)
                            }
                        ]
                    };
                } else {
                    error = {
                        code: -1,
                        message: lookupData.error || "DNS lookup failed"
                    };
                }
            } else if (toolName === 'dns_debug') {
                const debugResult = await handleDNSDebugTool(toolArgs);
                const debugData = await debugResult.json();

                if (debugData.success) {
                    result = {
                        content: [
                            {
                                type: "text",
                                text: formatDNSDebugResult(debugData.result)
                            }
                        ]
                    };
                } else {
                    error = {
                        code: -1,
                        message: debugData.error || "DNS debug failed"
                    };
                }
            } else {
                error = {
                    code: -32601,
                    message: `Unknown tool: ${toolName}`
                };
            }
            break;

        case 'resources/list':
            result = {
                resources: Object.values(MCP_RESOURCES)
            };
            break;

        case 'resources/read':
            const { uri } = params;
            const resourceId = uri.split('/').pop();
            const resourceResult = handleMCPResource(resourceId);
            const resourceData = await resourceResult.json();

            if (resourceResult.status === 200) {
                result = {
                    contents: [
                        {
                            uri: uri,
                            mimeType: resourceData.mimeType,
                            text: typeof resourceData.content === 'string'
                                ? resourceData.content
                                : JSON.stringify(resourceData.content, null, 2)
                        }
                    ]
                };
            } else {
                error = {
                    code: -1,
                    message: resourceData.error || "Resource not found"
                };
            }
            break;

        default:
            error = {
                code: -32601,
                message: `Method not found: ${method}`
            };
    }

    const response = {
        jsonrpc: "2.0",
        id: id
    };

    if (error) {
        response.error = error;
    } else {
        response.result = result;
    }

    return response;
}

// 处理标准 MCP 协议请求
async function handleMCPProtocol(request) {
    try {
        const data = await request.json();
        const result = await processMCPMessage(data);

        return new Response(JSON.stringify(result), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (parseError) {
        return new Response(JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
                code: -32700,
                message: "Parse error",
                data: parseError.message
            }
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 格式化 DNS 查询结果
function formatDNSResult(result) {
    let text = `DNS 查询结果:\n`;
    text += `域名: ${result.domain}\n`;
    text += `记录类型: ${result.type}\n`;
    text += `查询时间: ${result.timestamp}\n`;
    text += `成功服务器: ${result.successful_servers}/${result.total_servers}\n`;

    if (result.answers && result.answers.length > 0) {
        text += `\n解析结果:\n`;
        result.answers.forEach((answer, index) => {
            text += `  ${index + 1}. ${answer.data} (TTL: ${answer.ttl}s)\n`;
        });

        if (result.servers_used) {
            text += `\n使用的服务器: ${result.servers_used.join(', ')}\n`;
        }

        if (result.consensus > 1) {
            text += `共识度: ${result.consensus} 个服务器返回相同结果\n`;
        }
    } else {
        text += `\n没有找到记录\n`;
    }

    return text;
}

// 格式化 DNS 调试结果
function formatDNSDebugResult(result) {
    let text = `DNS 调试结果:\n`;
    text += `域名: ${result.query.domain}\n`;
    text += `记录类型: ${result.query.type}\n`;
    text += `总耗时: ${result.totalTime}ms\n`;
    text += `成功服务器: ${result.summary.successfulServers}/${result.summary.totalServers}\n`;
    text += `平均响应时间: ${result.summary.averageResponseTime}ms\n\n`;

    if (result.finalResult) {
        text += `最终结果 (共识度: ${result.finalResult.consensus}):\n`;
        result.finalResult.answers.forEach((answer, index) => {
            text += `  ${index + 1}. ${answer.data} (TTL: ${answer.ttl}s)\n`;
        });
        text += `\n使用的服务器: ${result.finalResult.serverNames.join(', ')}\n\n`;
    }

    text += `各服务器详细结果:\n`;
    result.serverResults.forEach((server, index) => {
        const status = server.success ? '✅' : '❌';
        text += `${status} ${server.serverName}: ${server.responseTime}ms\n`;
        if (server.success && server.answers.length > 0) {
            server.answers.forEach(answer => {
                text += `    ${answer.data} (TTL: ${answer.ttl}s)\n`;
            });
        } else if (server.error) {
            text += `    错误: ${server.error}\n`;
        }
    });

    return text;
}

// 处理MCP服务器信息请求
function handleMCPInfo() {
    return new Response(JSON.stringify({
        ...MCP_SERVER_INFO,
        capabilities: {
            tools: Object.keys(MCP_TOOLS).length > 0,
            resources: Object.keys(MCP_RESOURCES).length > 0,
            prompts: false
        }
    }), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

// 处理MCP工具列表请求
function handleMCPTools() {
    return new Response(JSON.stringify({
        tools: Object.values(MCP_TOOLS)
    }), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

// 处理MCP资源列表请求
function handleMCPResources() {
    return new Response(JSON.stringify({
        resources: Object.values(MCP_RESOURCES)
    }), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

// 处理MCP资源内容请求
function handleMCPResource(resourceId) {
    if (resourceId === 'servers') {
        return new Response(JSON.stringify({
            uri: "doh://servers/list",
            mimeType: "application/json",
            content: DOH_SERVERS
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } else if (resourceId === 'types') {
        return new Response(JSON.stringify({
            uri: "dns://types/supported",
            mimeType: "application/json",
            content: DNS_TYPES
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    return new Response(JSON.stringify({
        error: "Resource not found"
    }), {
        status: 404,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

// 处理MCP工具调用请求
async function handleMCPToolCall(request) {
    try {
        const data = await request.json();
        const { tool, arguments: args } = data;

        if (!tool || !args) {
            return new Response(JSON.stringify({
                error: "Bad request",
                message: "Missing tool or arguments"
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        if (tool === 'dns_lookup') {
            return handleDNSLookupTool(args);
        } else if (tool === 'dns_debug') {
            return handleDNSDebugTool(args);
        }

        return new Response(JSON.stringify({
            error: "Tool not found",
            message: `Unknown tool: ${tool}`
        }), {
            status: 404,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: "Invalid request",
            message: error.message
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// DNS查询工具实现
async function handleDNSLookupTool(args) {
    const { domain, type = 'A', timeout = 500 } = args;

    if (!domain) {
        return new Response(JSON.stringify({
            error: "Missing domain parameter"
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    // 验证域名格式
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        return new Response(JSON.stringify({
            error: "Invalid domain format"
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    // 验证查询类型
    if (!(type.toUpperCase() in DNS_TYPES)) {
        return new Response(JSON.stringify({
            error: `Unsupported DNS type: ${type}`
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    try {
        // 执行DNS查询
        const results = await queryMultipleDoH(domain, type.toUpperCase(), timeout);

        if (results.success.length === 0) {
            return new Response(JSON.stringify({
                success: false,
                error: "All DoH servers failed",
                failed_servers: results.failed.map(f => ({
                    server: f.server,
                    serverName: f.serverName,
                    error: f.error
                }))
            }), {
                status: 503,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        // 获取最佳结果
        const bestResult = getBestResult(results);

        return new Response(JSON.stringify({
            success: true,
            result: {
                domain: domain,
                type: type.toUpperCase(),
                answers: bestResult.answers || [],
                consensus: bestResult.consensus || 1,
                successful_servers: results.success.length,
                total_servers: results.total,
                servers_used: bestResult.serverNames || [results.success[0]?.serverName],
                timestamp: new Date().toISOString()
            }
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: "DNS lookup failed",
            message: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// DNS调试工具实现
async function handleDNSDebugTool(args) {
    const { domain, type = 'A', timeout = 2000 } = args;

    if (!domain) {
        return new Response(JSON.stringify({
            error: "Missing domain parameter"
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    // 验证域名格式
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        return new Response(JSON.stringify({
            error: "Invalid domain format"
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    // 验证查询类型
    if (!(type.toUpperCase() in DNS_TYPES)) {
        return new Response(JSON.stringify({
            error: `Unsupported DNS type: ${type}`
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    try {
        // 执行详细的调试查询
        const debugResults = await queryMultipleDoHDebug(domain, type.toUpperCase(), timeout);

        return new Response(JSON.stringify({
            success: true,
            result: debugResults
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: "DNS debug failed",
            message: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 调试专用的并行查询函数，返回所有服务器的详细结果
async function queryMultipleDoHDebug(domain, type = 'A', timeoutMs = 500) {
    const serverEntries = Object.entries(DOH_SERVERS);
    const startTime = Date.now();

    const promises = serverEntries.map(async ([name, url]) => {
        const serverStartTime = Date.now();
        try {
            const result = await queryDoHServer(url, domain, type, timeoutMs);
            const serverEndTime = Date.now();

            return {
                serverName: name,
                serverUrl: url,
                success: result.success,
                responseTime: serverEndTime - serverStartTime,
                answers: result.answers || [],
                error: result.error || null,
                timestamp: new Date(serverStartTime).toISOString()
            };
        } catch (error) {
            const serverEndTime = Date.now();
            return {
                serverName: name,
                serverUrl: url,
                success: false,
                responseTime: serverEndTime - serverStartTime,
                answers: [],
                error: error.message,
                timestamp: new Date(serverStartTime).toISOString()
            };
        }
    });

    const results = await Promise.allSettled(promises);
    const endTime = Date.now();

    const serverResults = results.map((result, index) => {
        if (result.status === 'fulfilled') {
            return result.value;
        } else {
            const [serverName, serverUrl] = serverEntries[index];
            return {
                serverName: serverName,
                serverUrl: serverUrl,
                success: false,
                responseTime: timeoutMs,
                answers: [],
                error: result.reason?.message || '未知错误',
                timestamp: new Date().toISOString()
            };
        }
    });

    const successfulResults = serverResults.filter(r => r.success && r.answers.length > 0);

    // 计算最终结果（使用原有逻辑）
    let finalResult = null;
    if (successfulResults.length > 0) {
        const mockResults = {
            success: successfulResults.map(r => ({
                answers: r.answers,
                server: r.serverUrl,
                serverName: r.serverName
            }))
        };
        finalResult = getBestResult(mockResults);
    }

    return {
        query: {
            domain: domain,
            type: type,
            timeout: timeoutMs,
            timestamp: new Date(startTime).toISOString()
        },
        totalTime: endTime - startTime,
        serverResults: serverResults,
        summary: {
            totalServers: serverResults.length,
            successfulServers: successfulResults.length,
            failedServers: serverResults.length - successfulResults.length,
            averageResponseTime: successfulResults.length > 0
                ? Math.round(successfulResults.reduce((sum, r) => sum + r.responseTime, 0) / successfulResults.length)
                : 0
        },
        finalResult: finalResult ? {
            answers: finalResult.answers,
            consensus: finalResult.consensus,
            serverNames: finalResult.serverNames,
            servers: finalResult.servers
        } : null
    };
}

// 生成调试页面HTML
function getDebugHTML() {
    const serverOptions = Object.keys(DOH_SERVERS).map(name =>
        `<option value="${name}">${name}</option>`
    ).join('');

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DoH 调试工具</title>
  <style>
      * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
      }
      
      body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
          padding: 20px;
      }
      
      .container {
          max-width: 1200px;
          margin: 0 auto;
          background: white;
          border-radius: 15px;
          box-shadow: 0 20px 40px rgba(0,0,0,0.1);
          overflow: hidden;
      }
      
      .header {
          background: linear-gradient(135deg, #4f46e5, #7c3aed);
          color: white;
          padding: 30px;
          text-align: center;
      }
      
      .header h1 {
          font-size: 2.5rem;
          margin-bottom: 10px;
      }
      
      .header p {
          opacity: 0.9;
          font-size: 1.1rem;
      }
      
      .content {
          padding: 30px;
      }
      
      .form-section {
          background: #f8fafc;
          padding: 25px;
          border-radius: 10px;
          margin-bottom: 30px;
      }
      
      .form-group {
          margin-bottom: 20px;
      }
      
      .form-group label {
          display: block;
          margin-bottom: 8px;
          font-weight: 600;
          color: #374151;
      }
      
      .form-group input, .form-group select {
          width: 100%;
          padding: 12px 15px;
          border: 2px solid #e5e7eb;
          border-radius: 8px;
          font-size: 16px;
          transition: border-color 0.3s;
      }
      
      .form-group input:focus, .form-group select:focus {
          outline: none;
          border-color: #4f46e5;
          box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
      }
      
      .form-row {
          display: grid;
          grid-template-columns: 2fr 1fr 1fr;
          gap: 20px;
      }
      
      .query-btn {
          background: linear-gradient(135deg, #4f46e5, #7c3aed);
          color: white;
          border: none;
          padding: 15px 30px;
          border-radius: 8px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: transform 0.2s, box-shadow 0.2s;
          width: 100%;
      }
      
      .query-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 20px rgba(79, 70, 229, 0.3);
      }
      
      .query-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
          transform: none;
      }
      
      .loading {
          display: none;
          text-align: center;
          padding: 20px;
          color: #6b7280;
      }
      
      .spinner {
          display: inline-block;
          width: 20px;
          height: 20px;
          border: 2px solid #e5e7eb;
          border-radius: 50%;
          border-top-color: #4f46e5;
          animation: spin 1s linear infinite;
          margin-right: 10px;
      }
      
      @keyframes spin {
          to { transform: rotate(360deg); }
      }
      
      .results {
          display: none;
      }
      
      .summary-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 20px;
          margin-bottom: 30px;
      }
      
      .summary-card {
          background: linear-gradient(135deg, #10b981, #059669);
          color: white;
          padding: 20px;
          border-radius: 10px;
          text-align: center;
      }
      
      .summary-card h3 {
          font-size: 2rem;
          margin-bottom: 5px;
      }
      
      .summary-card p {
          opacity: 0.9;
      }
      
      .final-result {
          background: #f0f9ff;
          border: 2px solid #0ea5e9;
          border-radius: 10px;
          padding: 20px;
          margin-bottom: 30px;
      }
      
      .final-result h3 {
          color: #0369a1;
          margin-bottom: 15px;
      }
      
      .server-results {
          display: grid;
          gap: 15px;
      }
      
      .server-result {
          border: 2px solid #e5e7eb;
          border-radius: 10px;
          padding: 20px;
          transition: transform 0.2s;
      }
      
      .server-result:hover {
          transform: translateY(-2px);
          box-shadow: 0 5px 15px rgba(0,0,0,0.1);
      }
      
      .server-result.success {
          border-color: #10b981;
          background: #f0fdf4;
      }
      
      .server-result.failed {
          border-color: #ef4444;
          background: #fef2f2;
      }
      
      .server-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 15px;
      }
      
      .server-name {
          font-weight: 600;
          font-size: 1.1rem;
      }
      
      .server-result.success .server-name {
          color: #065f46;
      }
      
      .server-result.failed .server-name {
          color: #dc2626;
      }
      
      .response-time {
          background: rgba(255,255,255,0.8);
          padding: 5px 10px;
          border-radius: 15px;
          font-size: 0.9rem;
          font-weight: 600;
      }
      
      .server-answers {
          margin-top: 10px;
      }
      
      .answer-item {
          background: rgba(255,255,255,0.6);
          padding: 8px 12px;
          border-radius: 6px;
          margin-bottom: 5px;
          font-family: 'Courier New', monospace;
          font-size: 0.9rem;
      }
      
      .error-message {
          color: #dc2626;
          font-style: italic;
          margin-top: 10px;
      }
      
      @media (max-width: 768px) {
          .form-row {
              grid-template-columns: 1fr;
          }
          
          .summary-cards {
              grid-template-columns: repeat(2, 1fr);
          }
      }
  </style>
</head>
<body>
  <div class="container">
      <div class="header">
          <h1>🔍 DoH 调试工具</h1>
          <p>测试各个 DNS over HTTPS 服务器的响应情况</p>
      </div>
      
      <div class="content">
          <div class="form-section">
              <div class="form-row">
                  <div class="form-group">
                      <label for="domain">查询域名</label>
                      <input type="text" id="domain" placeholder="例如: google.com" value="google.com">
                  </div>
                  <div class="form-group">
                      <label for="type">记录类型</label>
                      <select id="type">
                          <option value="A">A</option>
                          <option value="AAAA">AAAA</option>
                          <option value="CNAME">CNAME</option>
                          <option value="MX">MX</option>
                          <option value="TXT">TXT</option>
                          <option value="NS">NS</option>
                          <option value="PTR">PTR</option>
                          <option value="SRV">SRV</option>
                          <option value="SOA">SOA</option>
                      </select>
                  </div>
                  <div class="form-group">
                      <label for="timeout">超时时间 (ms)</label>
                      <input type="number" id="timeout" value="2000" min="100" max="10000" step="100">
                  </div>
              </div>
              <button class="query-btn" onclick="performQuery()">
                  🚀 开始查询
              </button>
          </div>
          
          <div class="loading" id="loading">
              <div class="spinner"></div>
              正在查询各个 DoH 服务器...
          </div>
          
          <div class="results" id="results">
              <!-- 结果将在这里显示 -->
          </div>
      </div>
  </div>

  <script>
      async function performQuery() {
          const domain = document.getElementById('domain').value.trim();
          const type = document.getElementById('type').value;
          const timeout = parseInt(document.getElementById('timeout').value);
          
          if (!domain) {
              alert('请输入要查询的域名');
              return;
          }
          
          const queryBtn = document.querySelector('.query-btn');
          const loading = document.getElementById('loading');
          const results = document.getElementById('results');
          
          // 显示加载状态
          queryBtn.disabled = true;
          loading.style.display = 'block';
          results.style.display = 'none';
          
          try {
              const response = await fetch('/debug', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json',
                  },
                  body: JSON.stringify({
                      domain: domain,
                      type: type,
                      timeout: timeout
                  })
              });
              
              const data = await response.json();
              
              if (!response.ok) {
                  throw new Error(data.error || '查询失败');
              }
              
              displayResults(data);
              
          } catch (error) {
              results.innerHTML = \`
                  <div class="server-result failed">
                      <div class="server-header">
                          <span class="server-name">❌ 查询失败</span>
                      </div>
                      <div class="error-message">\${error.message}</div>
                  </div>
              \`;
              results.style.display = 'block';
          } finally {
              queryBtn.disabled = false;
              loading.style.display = 'none';
          }
      }
      
      function displayResults(data) {
          const results = document.getElementById('results');
          
          let html = \`
              <div class="summary-cards">
                  <div class="summary-card">
                      <h3>\${data.summary.totalServers}</h3>
                      <p>总服务器数</p>
                  </div>
                  <div class="summary-card">
                      <h3>\${data.summary.successfulServers}</h3>
                      <p>成功响应</p>
                  </div>
                  <div class="summary-card">
                      <h3>\${data.summary.failedServers}</h3>
                      <p>失败响应</p>
                  </div>
                  <div class="summary-card">
                      <h3>\${data.summary.averageResponseTime}ms</h3>
                      <p>平均响应时间</p>
                  </div>
              </div>
          \`;
          
          if (data.finalResult) {
              html += \`
                  <div class="final-result">
                      <h3>🎯 最终返回结果 (共识度: \${data.finalResult.consensus})</h3>
                      <div class="server-answers">
                          \${data.finalResult.answers.map(answer => 
                              \`<div class="answer-item">\${answer.data} (TTL: \${answer.ttl}s)</div>\`
                          ).join('')}
                      </div>
                      <p style="margin-top: 10px; color: #6b7280;">
                          使用的服务器: \${data.finalResult.serverNames.join(', ')}
                      </p>
                  </div>
              \`;
          }
          
          html += '<h3 style="margin-bottom: 20px;">📊 各服务器详细结果</h3>';
          html += '<div class="server-results">';
          
          data.serverResults.forEach(server => {
              const statusClass = server.success ? 'success' : 'failed';
              const statusIcon = server.success ? '✅' : '❌';
              
              html += \`
                  <div class="server-result \${statusClass}">
                      <div class="server-header">
                          <span class="server-name">\${statusIcon} \${server.serverName}</span>
                          <span class="response-time">\${server.responseTime}ms</span>
                      </div>
                      <div style="font-size: 0.9rem; color: #6b7280; margin-bottom: 10px;">
                          \${server.serverUrl}
                      </div>
              \`;
              
              if (server.success && server.answers.length > 0) {
                  html += '<div class="server-answers">';
                  server.answers.forEach(answer => {
                      html += \`<div class="answer-item">\${answer.data} (TTL: \${answer.ttl}s)</div>\`;
                  });
                  html += '</div>';
              } else if (server.error) {
                  html += \`<div class="error-message">错误: \${server.error}</div>\`;
              } else {
                  html += '<div class="error-message">无结果返回</div>';
              }
              
              html += '</div>';
          });
          
          html += '</div>';
          
          results.innerHTML = html;
          results.style.display = 'block';
      }
      
      // 回车键查询
      document.getElementById('domain').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
              performQuery();
          }
      });
  </script>
</body>
</html>`;
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 处理CORS预检请求
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Accept',
                    'Access-Control-Max-Age': '86400',
                }
            });
        }

        // 根路径返回使用说明
        if (url.pathname === '/') {
            return new Response(`
DoH (DNS over HTTPS) 服务 + MCP Server

=== DoH API ===
使用方法:
GET  /dns-query?name=example.com&type=A
POST /dns-query (带有DNS查询包)

支持的查询类型: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, SOA

示例:
- /dns-query?name=google.com&type=A
- /dns-query?name=cloudflare.com&type=AAAA
- /dns-query?name=example.com&type=MX

返回格式:
- 默认: JSON格式 (向后兼容)
- 标准DoH: 添加 Accept: application/dns-message 头部
- 强制JSON: 添加 ?format=json 参数

调试工具:
- /debug - 可视化调试界面，查看各个DoH服务器的详细响应

=== MCP (Model Context Protocol) API ===
MCP端点:
- GET  /mcp - 服务器信息
- GET  /mcp/tools - 可用工具列表
- POST /mcp/tools/call - 调用工具
- GET  /mcp/resources - 可用资源列表
- GET  /mcp/resources/{id} - 获取资源内容
- GET  /mcp/sse - SSE (Server-Sent Events) 连接
- POST /mcp/sse - 通过SSE发送MCP消息
- GET  /mcp/streamable-http - StreamableHttp 连接
- POST /mcp/streamable-http - 通过StreamableHttp发送MCP消息

MCP工具:
- dns_lookup: 执行DNS查询
- dns_debug: 获取详细的DNS调试信息

MCP使用示例:
curl -X POST /mcp/tools/call \\
-H "Content-Type: application/json" \\
-d '{"tool": "dns_lookup", "arguments": {"domain": "example.com", "type": "A"}}'

MCP SSE使用示例:
curl -N -H "Accept: text/event-stream" /mcp/sse

MCP StreamableHttp使用示例:
curl -X POST /mcp/streamable-http \\
-H "Content-Type: application/json" \\
-d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "dns_lookup", "arguments": {"domain": "example.com", "type": "A"}}, "id": 1}'

特性:
- 并行查询${Object.keys(DOH_SERVERS).length}个公共DoH服务器
- 500ms超时保护
- 返回公认的解析结果
- 支持标准DoH格式 (RFC 8484)
- 向后兼容JSON响应
- 完整的MCP协议支持，包括SSE (Server-Sent Events) 和 StreamableHttp

标准DoH客户端示例:
curl -H "Accept: application/dns-message" \\
   "https://your-worker.dev/dns-query?name=example.com&type=A"
    `, {
                headers: {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        // 处理DNS查询
        if (url.pathname === '/dns-query') {
            try {
                let domain, type, acceptHeader;

                if (request.method === 'GET') {
                    domain = url.searchParams.get('name');
                    type = url.searchParams.get('type') || 'A';
                    acceptHeader = request.headers.get('Accept') || '';

                    if (!domain) {
                        return new Response('缺少name参数', {
                            status: 400,
                            headers: { 'Access-Control-Allow-Origin': '*' }
                        });
                    }
                } else if (request.method === 'POST') {
                    // 处理POST请求的DNS查询包
                    const contentType = request.headers.get('Content-Type');
                    acceptHeader = request.headers.get('Accept') || '';

                    if (contentType === 'application/dns-message') {
                        // 标准DoH POST请求，解析DNS查询包
                        try {
                            const dnsQueryBuffer = await request.arrayBuffer();
                            if (dnsQueryBuffer.byteLength < 12) {
                                return new Response('无效的DNS查询包', {
                                    status: 400,
                                    headers: { 'Access-Control-Allow-Origin': '*' }
                                });
                            }

                            // 解析DNS查询包获取域名和查询类型
                            const view = new DataView(dnsQueryBuffer);
                            const qdcount = view.getUint16(4); // 问题数量
                            
                            if (qdcount !== 1) {
                                return new Response('只支持单个DNS查询', {
                                    status: 400,
                                    headers: { 'Access-Control-Allow-Origin': '*' }
                                });
                            }

                            // 解析问题部分
                            let offset = 12;
                            const labels = [];
                            
                            // 解析域名
                            while (offset < dnsQueryBuffer.byteLength) {
                                const len = view.getUint8(offset);
                                if (len === 0) {
                                    offset++;
                                    break;
                                }
                                offset++;
                                if (offset + len <= dnsQueryBuffer.byteLength) {
                                    const label = new Uint8Array(dnsQueryBuffer, offset, len);
                                    labels.push(String.fromCharCode(...label));
                                    offset += len;
                                } else {
                                    throw new Error('域名解析错误');
                                }
                            }
                            
                            domain = labels.join('.');
                            
                            // 读取查询类型
                            if (offset + 4 <= dnsQueryBuffer.byteLength) {
                                const qtype = view.getUint16(offset);
                                // 查找对应的类型名称
                                for (const [typeName, typeCode] of Object.entries(DNS_TYPES)) {
                                    if (typeCode === qtype) {
                                        type = typeName;
                                        break;
                                    }
                                }
                                if (!type) {
                                    type = 'A'; // 默认类型
                                }
                            } else {
                                throw new Error('查询类型解析错误');
                            }

                            if (!domain) {
                                return new Response('无法解析DNS查询包中的域名', {
                                    status: 400,
                                    headers: { 'Access-Control-Allow-Origin': '*' }
                                });
                            }
                        } catch (error) {
                            return new Response(`DNS查询包解析错误: ${error.message}`, {
                                status: 400,
                                headers: { 'Access-Control-Allow-Origin': '*' }
                            });
                        }
                    } else {
                        return new Response('POST请求的Content-Type必须是application/dns-message', {
                            status: 400,
                            headers: { 'Access-Control-Allow-Origin': '*' }
                        });
                    }
                } else {
                    return new Response('不支持的方法', {
                        status: 405,
                        headers: { 'Access-Control-Allow-Origin': '*' }
                    });
                }

                // 验证域名格式
                if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
                    return new Response('无效的域名格式', {
                        status: 400,
                        headers: { 'Access-Control-Allow-Origin': '*' }
                    });
                }

                // 验证查询类型
                if (!(type.toUpperCase() in DNS_TYPES)) {
                    return new Response(`不支持的查询类型: ${type}`, {
                        status: 400,
                        headers: { 'Access-Control-Allow-Origin': '*' }
                    });
                }

                console.log(`查询域名: ${domain}, 类型: ${type}`);

                // 执行并行查询
                const results = await queryMultipleDoH(domain, type.toUpperCase(), 500);

                console.log(`成功: ${results.success.length}, 失败: ${results.failed.length}`);

                if (results.success.length === 0) {
                    const errorResponse = {
                        error: '所有DoH服务器查询失败',
                        failed_servers: results.failed.map(f => ({
                            server: f.server,
                            serverName: f.serverName,
                            error: f.error
                        }))
                    };

                    return new Response(JSON.stringify(errorResponse), {
                        status: 503,
                        headers: {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }

                // 获取最佳结果
                const bestResult = getBestResult(results);

                // 检查Accept头部，决定返回格式
                const wantsDnsMessage = acceptHeader.includes('application/dns-message');
                const wantsJson = acceptHeader.includes('application/json') ||
                    url.searchParams.get('format') === 'json' ||
                    !wantsDnsMessage; // 默认返回JSON以保持兼容性

                if (wantsDnsMessage && bestResult.answers && bestResult.answers.length > 0) {
                    // 返回标准DNS消息格式
                    const dnsResponse = buildDNSResponse(domain, type.toUpperCase(), bestResult.answers);

                    return new Response(dnsResponse, {
                        headers: {
                            'Content-Type': 'application/dns-message',
                            'Access-Control-Allow-Origin': '*',
                            'Cache-Control': 'public, max-age=300'
                        }
                    });
                } else {
                    // 返回JSON格式（向后兼容）
                    const jsonResponse = {
                        domain: domain,
                        type: type.toUpperCase(),
                        answers: bestResult.answers || [],
                        consensus: bestResult.consensus || 1,
                        successful_servers: results.success.length,
                        total_servers: results.total,
                        servers_used: bestResult.servers || [results.success[0]?.server],
                        server_names_used: bestResult.serverNames || [results.success[0]?.serverName],
                        timestamp: new Date().toISOString()
                    };

                    return new Response(JSON.stringify(jsonResponse), {
                        headers: {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*',
                            'Cache-Control': 'public, max-age=300'
                        }
                    });
                }

            } catch (error) {
                console.error('DNS查询错误:', error);

                return new Response(JSON.stringify({
                    error: '内部服务器错误',
                    message: error.message
                }), {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }

        // 调试路由
        if (url.pathname === '/debug') {
            if (request.method === 'GET') {
                // 返回调试页面
                return new Response(getDebugHTML(), {
                    headers: {
                        'Content-Type': 'text/html; charset=utf-8',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } else if (request.method === 'POST') {
                // 处理调试查询
                try {
                    const data = await request.json();
                    const { domain, type = 'A', timeout = 500 } = data;

                    if (!domain) {
                        return new Response(JSON.stringify({ error: '缺少domain参数' }), {
                            status: 400,
                            headers: {
                                'Content-Type': 'application/json',
                                'Access-Control-Allow-Origin': '*'
                            }
                        });
                    }

                    // 验证域名格式
                    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
                        return new Response(JSON.stringify({ error: '无效的域名格式' }), {
                            status: 400,
                            headers: {
                                'Content-Type': 'application/json',
                                'Access-Control-Allow-Origin': '*'
                            }
                        });
                    }

                    // 验证查询类型
                    if (!(type.toUpperCase() in DNS_TYPES)) {
                        return new Response(JSON.stringify({ error: `不支持的查询类型: ${type}` }), {
                            status: 400,
                            headers: {
                                'Content-Type': 'application/json',
                                'Access-Control-Allow-Origin': '*'
                            }
                        });
                    }

                    // 执行详细的调试查询
                    const debugResults = await queryMultipleDoHDebug(domain, type.toUpperCase(), timeout);

                    return new Response(JSON.stringify(debugResults, null, 2), {
                        headers: {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        }
                    });

                } catch (error) {
                    return new Response(JSON.stringify({
                        error: '请求处理错误',
                        message: error.message
                    }), {
                        status: 500,
                        headers: {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }
            }
        }

        // MCP (Model Context Protocol) 支持
        if (url.pathname === '/mcp' || url.pathname.startsWith('/mcp/')) {
            return handleMCPRequest(request, url);
        }

        // 未知路径
        return new Response('未找到页面', {
            status: 404,
            headers: { 'Access-Control-Allow-Origin': '*' }
        });
    }
};