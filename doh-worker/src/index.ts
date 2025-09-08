import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// DNS record types mapping
const DNS_TYPES = {
    A: 1,
    AAAA: 28,
    CNAME: 5,
    MX: 15,
    TXT: 16,
    NS: 2,
    PTR: 12,
    SRV: 33,
    SOA: 6,
} as const;

// Public DoH servers configuration
const DOH_SERVERS = {
    DNSPod: "https://doh.pub/dns-query",
    Alidns: "https://dns.alidns.com/dns-query",
    "360": "https://doh.360.cn",
    Google: "https://dns.google/dns-query",
    Cloudflare: "https://cloudflare-dns.com/dns-query",
    Quad9: "https://dns.quad9.net/dns-query",
    "DNS.SB": "https://doh.dns.sb/dns-query",
    OpenDNS: "https://doh.opendns.com/dns-query",
    AdGuard: "https://dns.adguard-dns.com/dns-query",
} as const;

type DNSRecordType = keyof typeof DNS_TYPES;

interface DNSAnswer {
    type: number;
    ttl: number;
    data: string;
}

interface DNSQueryResult {
    answers: DNSAnswer[];
}

interface DoHServerResponse {
    success: boolean;
    server: string;
    serverName: string;
    result?: DNSQueryResult;
    answers?: DNSAnswer[];
    error?: string;
    responseTime?: number;
}

interface QueryResults {
    success: DoHServerResponse[];
    failed: DoHServerResponse[];
    total: number;
    consensus?: DNSAnswer[];
    bestResult?: DoHServerResponse;
}

// DNS query utilities
class DNSUtils {
    static encodeDomainName(domain: string): string {
        const parts = domain.split(".");
        let encoded = "";

        for (const part of parts) {
            if (part.length > 0) {
                encoded += String.fromCharCode(part.length) + part;
            }
        }

        encoded += "\0"; // 结束符
        return encoded;
    }

    static parseDomainName(buffer: ArrayBuffer, offset: number): string {
        const view = new DataView(buffer);
        const labels: string[] = [];
        let currentOffset = offset;
        let jumped = false;
        let maxJumps = 10; // 防止无限循环

        while (currentOffset < buffer.byteLength && maxJumps > 0) {
            const len = view.getUint8(currentOffset);

            if (len === 0) {
                // 域名结束
                break;
            }
            if ((len & 0xc0) === 0xc0) {
                // 压缩指针
                const pointer = ((len & 0x3f) << 8) | view.getUint8(currentOffset + 1);
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

        return labels.join(".");
    }

    static skipDomainName(buffer: ArrayBuffer, offset: number): number {
        const view = new DataView(buffer);
        let currentOffset = offset;

        while (currentOffset < buffer.byteLength) {
            const len = view.getUint8(currentOffset);

            if (len === 0) {
                return currentOffset + 1;
            }
            if ((len & 0xc0) === 0xc0) {
                return currentOffset + 2;
            }
            currentOffset += len + 1;
        }

        return currentOffset;
    }

    static buildDNSQuery(domain: string, type: DNSRecordType = "A"): Uint8Array {
        const typeCode = DNS_TYPES[type] || 1;

        // DNS头部 (12字节)
        const id = Math.floor(Math.random() * 65536);
        const flags = 0x0100; // 标准查询，期望递归
        const qdcount = 1; // 问题数量
        const ancount = 0; // 答案数量
        const nscount = 0; // 权威记录数量
        const arcount = 0; // 附加记录数量

        const header = new ArrayBuffer(12);
        const view = new DataView(header);

        view.setUint16(0, id);
        view.setUint16(2, flags);
        view.setUint16(4, qdcount);
        view.setUint16(6, ancount);
        view.setUint16(8, nscount);
        view.setUint16(10, arcount);

        // 问题部分
        const encodedDomain = this.encodeDomainName(domain);
        const question = new ArrayBuffer(encodedDomain.length + 4);
        const questionView = new Uint8Array(question);

        // 写入编码后的域名
        for (let i = 0; i < encodedDomain.length; i++) {
            questionView[i] = encodedDomain.charCodeAt(i);
        }

        // 写入查询类型和类别
        const questionDataView = new DataView(question);
        questionDataView.setUint16(encodedDomain.length, typeCode); // QTYPE
        questionDataView.setUint16(encodedDomain.length + 2, 1); // QCLASS (IN)

        // 合并头部和问题
        const query = new Uint8Array(header.byteLength + question.byteLength);
        query.set(new Uint8Array(header), 0);
        query.set(new Uint8Array(question), header.byteLength);

        return query;
    }

    static parseDNSResponse(response: ArrayBuffer): DNSQueryResult {
        const view = new DataView(response);

        if (response.byteLength < 12) {
            throw new Error("响应太短");
        }

        const flags = view.getUint16(2);
        const qdcount = view.getUint16(4);
        const ancount = view.getUint16(6);

        // 检查响应码
        const rcode = flags & 0x000f;
        if (rcode !== 0) {
            throw new Error(`DNS错误码: ${rcode}`);
        }

        if (ancount === 0) {
            return { answers: [] };
        }

        // 跳过问题部分
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
                if ((len & 0xc0) === 0xc0) {
                    offset += 2;
                    break;
                }
                offset += len + 1;
            }
            offset += 4; // 跳过QTYPE和QCLASS
        }

        const answers: DNSAnswer[] = [];

        // 解析答案记录
        for (let i = 0; i < ancount && offset < response.byteLength; i++) {
            try {
                // 跳过名称部分
                if ((view.getUint8(offset) & 0xc0) === 0xc0) {
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

                let data = "";
                if (type === 1 && rdlength === 4) {
                    // A记录
                    const ip = new Uint8Array(response, offset, 4);
                    data = Array.from(ip).join(".");
                } else if (type === 28 && rdlength === 16) {
                    // AAAA记录
                    const ip6 = new Uint8Array(response, offset, 16);
                    const parts: string[] = [];
                    for (let j = 0; j < 16; j += 2) {
                        parts.push(((ip6[j] << 8) | ip6[j + 1]).toString(16));
                    }
                    data = parts.join(":").replace(/(:0)+:/g, "::");
                } else if (type === 15) {
                    // MX记录
                    const priority = view.getUint16(offset);
                    const nameOffset = offset + 2;
                    const domainName = this.parseDomainName(response, nameOffset);
                    data = `${priority} ${domainName}`;
                } else if (type === 5) {
                    // CNAME记录
                    data = this.parseDomainName(response, offset);
                } else if (type === 2) {
                    // NS记录
                    data = this.parseDomainName(response, offset);
                } else if (type === 12) {
                    // PTR记录
                    data = this.parseDomainName(response, offset);
                } else if (type === 16) {
                    // TXT记录
                    let txtOffset = offset;
                    const txtParts: string[] = [];
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
                    data = txtParts.join("");
                } else if (type === 33) {
                    // SRV记录
                    const priority = view.getUint16(offset);
                    const weight = view.getUint16(offset + 2);
                    const port = view.getUint16(offset + 4);
                    const target = this.parseDomainName(response, offset + 6);
                    data = `${priority} ${weight} ${port} ${target}`;
                } else if (type === 6) {
                    // SOA记录
                    let soaOffset = offset;
                    const mname = this.parseDomainName(response, soaOffset);
                    soaOffset = this.skipDomainName(response, soaOffset);
                    const rname = this.parseDomainName(response, soaOffset);
                    soaOffset = this.skipDomainName(response, soaOffset);

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
                        data: data,
                    });
                }

                offset += rdlength;
            } catch (e) {
                break;
            }
        }

        return { answers };
    }
}

// DoH query service
class DoHService {
    static async queryDoHServer(
        server: string,
        serverName: string,
        domain: string,
        type: DNSRecordType,
        timeoutMs: number,
    ): Promise<DoHServerResponse> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
        const startTime = Date.now();

        try {
            const dnsQuery = DNSUtils.buildDNSQuery(domain, type);

            const response = await fetch(server, {
                method: "POST",
                headers: {
                    "Content-Type": "application/dns-message",
                    Accept: "application/dns-message",
                },
                body: dnsQuery,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const responseBuffer = await response.arrayBuffer();
            const result = DNSUtils.parseDNSResponse(responseBuffer);
            const responseTime = Date.now() - startTime;

            return {
                success: true,
                server: server,
                serverName: serverName,
                result: result,
                answers: result.answers,
                responseTime: responseTime,
            };
        } catch (error) {
            clearTimeout(timeoutId);
            const responseTime = Date.now() - startTime;
            return {
                success: false,
                server: server,
                serverName: serverName,
                error: error instanceof Error ? error.message : "Unknown error",
                responseTime: responseTime,
            };
        }
    }

    static async queryMultipleDoH(
        domain: string,
        type: DNSRecordType = "A",
        timeoutMs = 500,
    ): Promise<QueryResults> {
        const serverEntries = Object.entries(DOH_SERVERS);
        const promises = serverEntries.map(([name, url]) =>
            this.queryDoHServer(url, name, domain, type, timeoutMs),
        );

        const results = await Promise.allSettled(promises);

        const successResults: DoHServerResponse[] = [];
        const failedResults: DoHServerResponse[] = [];

        results.forEach((result, index) => {
            const [serverName] = serverEntries[index];

            if (result.status === "fulfilled") {
                if (result.value.success) {
                    successResults.push(result.value);
                } else {
                    failedResults.push(result.value);
                }
            } else {
                failedResults.push({
                    success: false,
                    server: serverEntries[index][1],
                    serverName: serverName,
                    error: result.reason?.message || "未知错误",
                });
            }
        });

        const consensus = this.findConsensus(successResults);
        const bestResult = this.getBestResult(successResults, consensus);

        return {
            success: successResults,
            failed: failedResults,
            total: Object.keys(DOH_SERVERS).length,
            consensus: consensus,
            bestResult: bestResult,
        };
    }

    private static findConsensus(results: DoHServerResponse[]): DNSAnswer[] {
        if (results.length === 0) return [];

        // 统计相同答案的频次
        const answerGroups = new Map<string, { answers: DNSAnswer[]; count: number }>();

        results.forEach((result) => {
            if (result.answers && result.answers.length > 0) {
                const key = result.answers
                    .map((a) => a.data)
                    .sort()
                    .join(",");
                if (!answerGroups.has(key)) {
                    answerGroups.set(key, { answers: result.answers, count: 0 });
                }
                answerGroups.get(key)!.count++;
            }
        });

        // 找到最高频次的答案
        let maxCount = 0;
        let consensusAnswers: DNSAnswer[] = [];

        for (const group of answerGroups.values()) {
            if (group.count > maxCount) {
                maxCount = group.count;
                consensusAnswers = group.answers;
            }
        }

        return consensusAnswers;
    }

    private static getBestResult(
        results: DoHServerResponse[],
        consensus: DNSAnswer[],
    ): DoHServerResponse | undefined {
        if (results.length === 0) return undefined;

        // 优先选择与共识一致且响应时间最快的结果
        const consensusKey = consensus
            .map((a) => a.data)
            .sort()
            .join(",");

        const consensusResults = results.filter((result) => {
            if (!result.answers || result.answers.length === 0) return false;
            const resultKey = result.answers
                .map((a) => a.data)
                .sort()
                .join(",");
            return resultKey === consensusKey;
        });

        if (consensusResults.length > 0) {
            return consensusResults.reduce((fastest, current) =>
                (current.responseTime || 0) < (fastest.responseTime || 0) ? current : fastest,
            );
        }

        // 如果没有共识，返回响应时间最快的结果
        return results.reduce((fastest, current) =>
            (current.responseTime || 0) < (fastest.responseTime || 0) ? current : fastest,
        );
    }
}

// Define our MCP agent with DoH tools
export class DoHMCP extends McpAgent {
    server = new McpServer({
        name: "DoH MCP Server",
        version: "1.0.0",
    });

    async init() {
        // DNS lookup tool
        this.server.tool(
            "dns_lookup",
            {
                domain: z.string().describe("要查询的域名，例如：google.com, example.org"),
                type: z
                    .enum(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "SOA"])
                    .default("A")
                    .describe("DNS记录类型"),
                timeout: z
                    .number()
                    .min(100)
                    .max(10000)
                    .default(500)
                    .describe("查询超时时间（毫秒）"),
            },
            async ({ domain, type, timeout }) => {
                try {
                    const results = await DoHService.queryMultipleDoH(
                        domain,
                        type as DNSRecordType,
                        timeout,
                    );

                    if (results.bestResult && results.bestResult.answers) {
                        const response = {
                            domain: domain,
                            type: type,
                            answers: results.bestResult.answers,
                            server: results.bestResult.serverName,
                            responseTime: results.bestResult.responseTime,
                            consensus: results.consensus,
                            totalServers: results.total,
                            successfulServers: results.success.length,
                            failedServers: results.failed.length,
                        };

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `DNS查询结果：\n域名: ${domain}\n类型: ${type}\n\n答案记录:\n${results.bestResult.answers
                                        .map((a) => `- ${a.data} (TTL: ${a.ttl}s)`)
                                        .join("\n")}\n\n响应服务器: ${results.bestResult.serverName}\n响应时间: ${results.bestResult.responseTime}ms\n成功/总计服务器: ${results.success.length}/${results.total}`,
                                },
                            ],
                        };
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: `DNS查询失败：\n域名: ${domain}\n类型: ${type}\n\n所有服务器都返回了错误或没有找到记录。\n失败的服务器: ${results.failed.length}/${results.total}`,
                            },
                        ],
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `DNS查询发生错误: ${error instanceof Error ? error.message : "未知错误"}`,
                            },
                        ],
                    };
                }
            },
        );

        // DNS debug tool
        this.server.tool(
            "dns_debug",
            {
                domain: z.string().describe("要调试的域名"),
                type: z
                    .enum(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "SOA"])
                    .default("A")
                    .describe("DNS记录类型"),
                timeout: z
                    .number()
                    .min(100)
                    .max(10000)
                    .default(2000)
                    .describe("调试查询的超时时间（毫秒）"),
            },
            async ({ domain, type, timeout }) => {
                try {
                    const results = await DoHService.queryMultipleDoH(
                        domain,
                        type as DNSRecordType,
                        timeout,
                    );

                    let debugText = `DNS调试信息：\n域名: ${domain}\n类型: ${type}\n总计服务器: ${results.total}\n\n`;

                    debugText += "=== 成功的服务器 ===\n";
                    if (results.success.length > 0) {
                        results.success.forEach((result) => {
                            debugText += `\n服务器: ${result.serverName}\nURL: ${result.server}\n响应时间: ${result.responseTime}ms\n`;
                            if (result.answers && result.answers.length > 0) {
                                debugText += "答案:\n";
                                result.answers.forEach((answer) => {
                                    debugText += `  - ${answer.data} (TTL: ${answer.ttl}s)\n`;
                                });
                            } else {
                                debugText += "答案: 无记录\n";
                            }
                        });
                    } else {
                        debugText += "无成功的服务器\n";
                    }

                    debugText += "\n=== 失败的服务器 ===\n";
                    if (results.failed.length > 0) {
                        results.failed.forEach((result) => {
                            debugText += `\n服务器: ${result.serverName}\nURL: ${result.server}\n响应时间: ${result.responseTime || 0}ms\n错误: ${result.error}\n`;
                        });
                    } else {
                        debugText += "无失败的服务器\n";
                    }

                    if (results.consensus && results.consensus.length > 0) {
                        debugText += "\n=== 共识结果 ===\n";
                        results.consensus.forEach((answer) => {
                            debugText += `- ${answer.data} (TTL: ${answer.ttl}s)\n`;
                        });
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: debugText,
                            },
                        ],
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `DNS调试发生错误: ${error instanceof Error ? error.message : "未知错误"}`,
                            },
                        ],
                    };
                }
            },
        );

        // Get DoH servers list tool
        this.server.tool(
            "get_doh_servers",
            {},
            async () => {
                const serverList = Object.entries(DOH_SERVERS)
                    .map(([name, url]) => `- ${name}: ${url}`)
                    .join("\n");

                return {
                    content: [
                        {
                            type: "text",
                            text: `可用的DoH服务器列表：\n\n${serverList}\n\n总计: ${Object.keys(DOH_SERVERS).length} 个服务器`,
                        },
                    ],
                };
            },
        );

        // DNS record types information tool
        this.server.tool(
            "dns_record_types",
            {},
            async () => {
                const typeInfo = `支持的DNS记录类型：

- A: IPv4地址记录
- AAAA: IPv6地址记录  
- CNAME: 别名记录
- MX: 邮件交换记录
- TXT: 文本记录(SPF/DKIM等)
- NS: 名称服务器记录
- PTR: 反向DNS查询(IP转域名)
- SRV: 服务记录
- SOA: 授权开始记录(域管理信息)

使用示例：
- 查询网站IP: dns_lookup(domain="example.com", type="A")
- 查询邮件服务器: dns_lookup(domain="example.com", type="MX")
- 查询文本记录: dns_lookup(domain="example.com", type="TXT")`;

                return {
                    content: [
                        {
                            type: "text",
                            text: typeInfo,
                        },
                    ],
                };
            },
        );
    }
}

export default {
    fetch(request: Request, env: Env, ctx: ExecutionContext) {
        const url = new URL(request.url);

        // MCP endpoints
        if (url.pathname === "/sse" || url.pathname === "/sse/message") {
            return DoHMCP.serveSSE("/sse").fetch(request, env, ctx);
        }

        if (url.pathname === "/mcp") {
            return DoHMCP.serve("/mcp").fetch(request, env, ctx);
        }

        // Web UI and API endpoints
        if (url.pathname === "/" || url.pathname === "/debug") {
            return env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
        }

        if (url.pathname === "/api/dns/lookup") {
            return this.handleApiDnsLookup(request);
        }

        if (url.pathname === "/api/dns/debug") {
            return this.handleApiDnsDebug(request);
        }

        // Legacy DoH endpoint for direct HTTP queries
        if (url.pathname === "/dns-query") {
            return this.handleDoHQuery(request);
        }

        // Static assets
        if (url.pathname.startsWith("/static/") || url.pathname.endsWith(".css") || url.pathname.endsWith(".js")) {
            return env.ASSETS.fetch(request);
        }

        return new Response("DoH MCP Server\n\nAvailable endpoints:\n- / : Web UI\n- /sse : MCP SSE\n- /mcp : MCP HTTP\n- /dns-query : Legacy DoH\n- /api/dns/* : REST API", {
            status: 200,
            headers: { "Content-Type": "text/plain" },
        });
    },

    async handleApiDnsLookup(request: Request): Promise<Response> {
        // Handle CORS preflight
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                    "Access-Control-Max-Age": "86400",
                },
            });
        }

        if (request.method !== "POST") {
            return new Response("Method not allowed", { status: 405 });
        }

        try {
            const body = await request.json() as { domain: string; type?: DNSRecordType; timeout?: number };
            const { domain, type = "A", timeout = 500 } = body;

            if (!domain) {
                return new Response(JSON.stringify({ error: "Domain is required" }), {
                    status: 400,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                });
            }

            const results = await DoHService.queryMultipleDoH(domain, type, timeout);

            const response = {
                success: results.bestResult !== undefined,
                domain: domain,
                type: type,
                result: results.bestResult?.result || { answers: [] },
                serverName: results.bestResult?.serverName || null,
                responseTime: results.bestResult?.responseTime || null,
                consensus: results.consensus || [],
                totalServers: results.total,
                successfulServers: results.success.length,
                failedServers: results.failed.length,
            };

            return new Response(JSON.stringify(response), {
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                },
            });
        } catch (error) {
            return new Response(
                JSON.stringify({
                    success: false,
                    error: error instanceof Error ? error.message : "Unknown error",
                }),
                {
                    status: 500,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                },
            );
        }
    },

    async handleApiDnsDebug(request: Request): Promise<Response> {
        // Handle CORS preflight
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                    "Access-Control-Max-Age": "86400",
                },
            });
        }

        if (request.method !== "POST") {
            return new Response("Method not allowed", { status: 405 });
        }

        try {
            const body = await request.json() as { domain: string; type?: DNSRecordType; timeout?: number };
            const { domain, type = "A", timeout = 2000 } = body;

            if (!domain) {
                return new Response(JSON.stringify({ error: "Domain is required" }), {
                    status: 400,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                });
            }

            const results = await DoHService.queryMultipleDoH(domain, type, timeout);

            const response = {
                success: true,
                domain: domain,
                type: type,
                servers: {
                    success: results.success,
                    failed: results.failed,
                },
                consensus: results.consensus || [],
                totalServers: results.total,
                successfulServers: results.success.length,
                failedServers: results.failed.length,
            };

            return new Response(JSON.stringify(response), {
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                },
            });
        } catch (error) {
            return new Response(
                JSON.stringify({
                    success: false,
                    error: error instanceof Error ? error.message : "Unknown error",
                }),
                {
                    status: 500,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                },
            );
        }
    },

    async handleDoHQuery(request: Request): Promise<Response> {
        try {
            const url = new URL(request.url);
            const domain = url.searchParams.get("name");
            const type = (url.searchParams.get("type") || "A") as DNSRecordType;

            if (!domain) {
                return new Response("Missing 'name' parameter", { status: 400 });
            }

            const results = await DoHService.queryMultipleDoH(domain, type, 500);

            if (results.bestResult && results.bestResult.result) {
                // Return raw DNS response for compatibility
                return new Response(JSON.stringify(results.bestResult.result), {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                });
            }

            return new Response(JSON.stringify({ answers: [] }), {
                status: 404,
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                },
            });
        } catch (error) {
            return new Response(
                JSON.stringify({
                    error: error instanceof Error ? error.message : "Unknown error",
                }),
                {
                    status: 500,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                },
            );
        }
    },
};
