/**
 * Cloudflare Worker Certificate Search Service + MCP Server
 * 
 * 这个Worker实现了一个证书搜索服务，支持：
 * - 通过 crt.sh API 查询证书信息
 * - 支持域名、组织、证书指纹等多种查询方式
 * - 支持MCP (Model Context Protocol) 协议
 * - 提供详细的证书信息和统计数据
 */

// MCP服务器信息
const MCP_SERVER_INFO = {
    name: "crt-mcp-server",
    version: "1.0.0",
    description: "Certificate search service with MCP support for AI models",
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
        },
        experimental: {
            streamableHttp: {}
        }
    }
};

// MCP工具定义
const MCP_TOOLS = {
    "cert_search": {
        name: "cert_search",
        description: "通过crt.sh搜索SSL/TLS证书。支持域名、组织名称、证书指纹等多种查询方式。返回证书的详细信息包括颁发者、有效期、主题备用名称等。适用于：安全审计、域名证书监控、证书透明度分析、SSL配置检查等场景。",
        inputSchema: {
            type: "object",
            properties: {
                query: {
                    type: "string",
                    description: "搜索查询。可以是域名(如example.com)、组织名称(如Google Inc)、证书指纹(SHA-1或SHA-256)、通配符域名(如*.example.com)。支持部分匹配搜索。"
                },
                type: {
                    type: "string",
                    enum: ["domain", "organization", "fingerprint", "serial"],
                    description: "查询类型。domain: 域名查询(默认)；organization: 按组织名称查询；fingerprint: 按证书指纹查询；serial: 按证书序列号查询。不同类型会影响搜索精度和结果范围。",
                    default: "domain"
                },
                limit: {
                    type: "number",
                    description: "返回结果的最大数量。建议值：10-100。较小值获得最相关结果，较大值获得更全面的信息。默认50条结果平衡详细度与性能。",
                    default: 50,
                    minimum: 1,
                    maximum: 1000
                },
                include_expired: {
                    type: "boolean",
                    description: "是否包含已过期的证书。true: 包含所有证书包括历史记录；false: 仅包含当前有效证书。默认包含过期证书以提供完整的历史视图。",
                    default: true
                },
                format: {
                    type: "string",
                    enum: ["summary", "detailed", "raw"],
                    description: "返回格式。summary: 简化摘要信息；detailed: 详细证书信息包含所有字段；raw: 原始API响应数据。推荐使用detailed获得最佳分析效果。",
                    default: "detailed"
                }
            },
            required: ["query"]
        }
    },
    "cert_stats": {
        name: "cert_stats",
        description: "获取域名或组织的证书统计信息。分析证书颁发趋势、CA分布、证书类型分布等统计数据。适用于：证书管理策略分析、安全态势评估、合规性检查、CA选择参考等场景。",
        inputSchema: {
            type: "object",
            properties: {
                query: {
                    type: "string",
                    description: "要分析的域名或组织名称。支持主域名分析(会包含所有子域名)或特定组织的证书统计。"
                },
                days: {
                    type: "number",
                    description: "统计时间范围（天数）。分析最近N天内的证书数据。常用值：30天(月度)、90天(季度)、365天(年度)。默认90天提供良好的趋势分析。",
                    default: 90,
                    minimum: 1,
                    maximum: 3650
                }
            },
            required: ["query"]
        }
    },
    "cert_monitor": {
        name: "cert_monitor",
        description: "监控域名的证书变化和到期情况。检查证书的有效性、到期时间、配置变更等。适用于：证书到期提醒、SSL配置监控、安全事件检测、证书续期管理等场景。",
        inputSchema: {
            type: "object",
            properties: {
                domain: {
                    type: "string",
                    description: "要监控的域名。建议使用具体的服务域名(如www.example.com)而非通配符，以获得准确的证书状态信息。"
                },
                check_chain: {
                    type: "boolean",
                    description: "是否检查完整的证书链。true: 验证整个证书链的有效性；false: 仅检查叶子证书。推荐启用以确保完整的SSL配置验证。",
                    default: true
                },
                warn_days: {
                    type: "number",
                    description: "到期预警天数。当证书在指定天数内到期时发出警告。常用值：30天(月度检查)、7天(紧急提醒)。默认30天提供充足的续期时间。",
                    default: 30,
                    minimum: 1,
                    maximum: 365
                }
            },
            required: ["domain"]
        }
    }
};

// MCP资源定义
const MCP_RESOURCES = {
    "crt_api": {
        uri: "crt://api/info",
        name: "Certificate Transparency API Info",
        description: "Information about crt.sh Certificate Transparency API",
        mimeType: "application/json"
    },
    "ca_list": {
        uri: "crt://ca/list",
        name: "Certificate Authorities List",
        description: "List of major Certificate Authorities",
        mimeType: "application/json"
    }
};

// crt.sh API 基础URL
const CRT_API_BASE = "https://crt.sh";

// 证书颁发机构映射
const CA_MAPPING = {
    "Let's Encrypt": "Let's Encrypt",
    "DigiCert": "DigiCert Inc",
    "GlobalSign": "GlobalSign",
    "Comodo": "Sectigo Limited",
    "Sectigo": "Sectigo Limited",
    "GeoTrust": "DigiCert Inc",
    "Thawte": "DigiCert Inc",
    "VeriSign": "DigiCert Inc",
    "Symantec": "DigiCert Inc",
    "RapidSSL": "DigiCert Inc",
    "Amazon": "Amazon",
    "Microsoft": "Microsoft Corporation",
    "Google": "Google Trust Services",
    "Cloudflare": "Cloudflare, Inc."
};

// 查询 crt.sh API
async function queryCrtSh(query, options = {}) {
    const {
        type = 'domain',
        limit = 50,
        include_expired = true,
        format = 'detailed'
    } = options;

    try {
        let apiUrl = `${CRT_API_BASE}/?output=json`;
        
        // 根据查询类型构建URL
        switch (type) {
            case 'domain':
                apiUrl += `&q=${encodeURIComponent(query)}`;
                break;
            case 'organization':
                apiUrl += `&O=${encodeURIComponent(query)}`;
                break;
            case 'fingerprint':
                apiUrl += `&sha1=${encodeURIComponent(query)}`;
                break;
            case 'serial':
                apiUrl += `&serial=${encodeURIComponent(query)}`;
                break;
            default:
                apiUrl += `&q=${encodeURIComponent(query)}`;
        }

        // 添加过期证书过滤
        if (!include_expired) {
            apiUrl += '&exclude=expired';
        }

        const response = await fetch(apiUrl, {
            headers: {
                'User-Agent': 'crt-mcp-server/1.0.0'
            }
        });

        if (!response.ok) {
            throw new Error(`crt.sh API错误: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();

        if (!Array.isArray(data)) {
            return [];
        }

        // 限制结果数量
        const limitedData = data.slice(0, limit);

        // 根据格式要求处理数据
        return formatCertificateData(limitedData, format);

    } catch (error) {
        throw new Error(`查询失败: ${error.message}`);
    }
}

// 格式化证书数据
function formatCertificateData(certificates, format) {
    if (format === 'raw') {
        return certificates;
    }

    return certificates.map(cert => {
        const commonData = {
            id: cert.id,
            logged_at: cert.logged_at,
            not_before: cert.not_before,
            not_after: cert.not_after,
            common_name: cert.common_name,
            matching_identities: cert.name_value ? cert.name_value.split('\n') : [],
            issuer_name: cert.issuer_name,
            serial_number: cert.serial_number,
            is_expired: new Date(cert.not_after) < new Date()
        };

        if (format === 'summary') {
            return {
                id: commonData.id,
                common_name: commonData.common_name,
                issuer: extractIssuerOrg(commonData.issuer_name),
                not_after: commonData.not_after,
                is_expired: commonData.is_expired,
                san_count: commonData.matching_identities.length
            };
        }

        // detailed format
        return {
            ...commonData,
            issuer_org: extractIssuerOrg(cert.issuer_name),
            issuer_ca: identifyCA(cert.issuer_name),
            days_until_expiry: calculateDaysUntilExpiry(cert.not_after),
            certificate_url: `${CRT_API_BASE}/?id=${cert.id}`,
            pem_url: `${CRT_API_BASE}/?d=${cert.id}`,
            validity_period_days: calculateValidityPeriod(cert.not_before, cert.not_after)
        };
    });
}

// 提取颁发者组织名称
function extractIssuerOrg(issuerName) {
    if (!issuerName) return 'Unknown';
    
    // 尝试提取 O= 字段
    const orgMatch = issuerName.match(/O=([^,]+)/);
    if (orgMatch) {
        return orgMatch[1].trim();
    }
    
    // 尝试提取 CN= 字段
    const cnMatch = issuerName.match(/CN=([^,]+)/);
    if (cnMatch) {
        return cnMatch[1].trim();
    }
    
    return issuerName;
}

// 识别证书颁发机构
function identifyCA(issuerName) {
    if (!issuerName) return 'Unknown';
    
    const upperIssuer = issuerName.toUpperCase();
    
    for (const [ca, fullName] of Object.entries(CA_MAPPING)) {
        if (upperIssuer.includes(ca.toUpperCase())) {
            return fullName;
        }
    }
    
    return extractIssuerOrg(issuerName);
}

// 计算到期天数
function calculateDaysUntilExpiry(notAfter) {
    const expiryDate = new Date(notAfter);
    const now = new Date();
    const diffTime = expiryDate.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}

// 计算证书有效期
function calculateValidityPeriod(notBefore, notAfter) {
    const startDate = new Date(notBefore);
    const endDate = new Date(notAfter);
    const diffTime = endDate.getTime() - startDate.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}

// 生成证书统计信息
async function generateCertStats(query, days = 90) {
    try {
        // 查询证书数据
        const certificates = await queryCrtSh(query, {
            type: 'domain',
            limit: 1000,
            include_expired: true,
            format: 'detailed'
        });

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);

        // 过滤指定时间范围内的证书
        const recentCerts = certificates.filter(cert => 
            new Date(cert.logged_at) >= cutoffDate
        );

        // 计算统计信息
        const stats = {
            query: query,
            analysis_period_days: days,
            total_certificates: recentCerts.length,
            active_certificates: recentCerts.filter(cert => !cert.is_expired).length,
            expired_certificates: recentCerts.filter(cert => cert.is_expired).length,
            
            // CA 分布
            ca_distribution: getCaDistribution(recentCerts),
            
            // 时间分布
            issuance_timeline: getIssuanceTimeline(recentCerts, days),
            
            // 到期分析
            expiry_analysis: getExpiryAnalysis(recentCerts),
            
            // 域名分析
            domain_analysis: getDomainAnalysis(recentCerts),
            
            // 证书类型分析
            certificate_types: getCertificateTypes(recentCerts)
        };

        return stats;

    } catch (error) {
        throw new Error(`统计分析失败: ${error.message}`);
    }
}

// 获取CA分布统计
function getCaDistribution(certificates) {
    const caCount = {};
    
    certificates.forEach(cert => {
        const ca = cert.issuer_ca || 'Unknown';
        caCount[ca] = (caCount[ca] || 0) + 1;
    });

    return Object.entries(caCount)
        .map(([ca, count]) => ({ ca, count }))
        .sort((a, b) => b.count - a.count);
}

// 获取颁发时间线
function getIssuanceTimeline(certificates, days) {
    const timeline = {};
    const today = new Date();
    
    // 初始化时间线
    for (let i = 0; i < days; i++) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split('T')[0];
        timeline[dateStr] = 0;
    }
    
    // 统计每日颁发数量
    certificates.forEach(cert => {
        const loggedDate = cert.logged_at.split('T')[0];
        if (timeline.hasOwnProperty(loggedDate)) {
            timeline[loggedDate]++;
        }
    });

    return Object.entries(timeline)
        .map(([date, count]) => ({ date, count }))
        .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}

// 获取到期分析
function getExpiryAnalysis(certificates) {
    const now = new Date();
    const analysis = {
        expiring_soon: 0,      // 30天内到期
        expiring_medium: 0,    // 30-90天内到期
        expiring_later: 0,     // 90天后到期
        already_expired: 0     // 已过期
    };

    certificates.forEach(cert => {
        const daysUntilExpiry = cert.days_until_expiry;
        
        if (cert.is_expired) {
            analysis.already_expired++;
        } else if (daysUntilExpiry <= 30) {
            analysis.expiring_soon++;
        } else if (daysUntilExpiry <= 90) {
            analysis.expiring_medium++;
        } else {
            analysis.expiring_later++;
        }
    });

    return analysis;
}

// 获取域名分析
function getDomainAnalysis(certificates) {
    const domainCount = {};
    let wildcardCount = 0;
    let sanTotal = 0;

    certificates.forEach(cert => {
        // 统计主域名
        if (cert.common_name) {
            const domain = cert.common_name.replace(/^\*\./, '');
            domainCount[domain] = (domainCount[domain] || 0) + 1;
            
            if (cert.common_name.startsWith('*.')) {
                wildcardCount++;
            }
        }

        // 统计SAN
        sanTotal += cert.matching_identities.length;
    });

    const topDomains = Object.entries(domainCount)
        .map(([domain, count]) => ({ domain, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

    return {
        unique_domains: Object.keys(domainCount).length,
        top_domains: topDomains,
        wildcard_certificates: wildcardCount,
        average_san_count: certificates.length > 0 ? Math.round(sanTotal / certificates.length) : 0
    };
}

// 获取证书类型分析
function getCertificateTypes(certificates) {
    const types = {
        single_domain: 0,      // 单域名证书
        wildcard: 0,           // 通配符证书
        multi_domain: 0,       // 多域名证书
        extended_validation: 0  // EV证书 (通过颁发者名称推测)
    };

    certificates.forEach(cert => {
        const sanCount = cert.matching_identities.length;
        const isWildcard = cert.common_name && cert.common_name.startsWith('*.');
        const isEV = cert.issuer_name && cert.issuer_name.includes('EV');

        if (isWildcard) {
            types.wildcard++;
        } else if (sanCount > 1) {
            types.multi_domain++;
        } else {
            types.single_domain++;
        }

        if (isEV) {
            types.extended_validation++;
        }
    });

    return types;
}

// 监控域名证书
async function monitorDomainCerts(domain, options = {}) {
    const {
        check_chain = true,
        warn_days = 30
    } = options;

    try {
        // 查询域名的当前证书
        const certificates = await queryCrtSh(domain, {
            type: 'domain',
            limit: 10,
            include_expired: false,
            format: 'detailed'
        });

        // 过滤出最相关的证书（完全匹配的域名）
        const exactMatches = certificates.filter(cert => 
            cert.common_name === domain || 
            cert.matching_identities.includes(domain)
        );

        const activeCerts = exactMatches.filter(cert => !cert.is_expired);

        const monitor = {
            domain: domain,
            check_time: new Date().toISOString(),
            active_certificates: activeCerts.length,
            certificates: activeCerts.map(cert => ({
                id: cert.id,
                common_name: cert.common_name,
                issuer_ca: cert.issuer_ca,
                not_after: cert.not_after,
                days_until_expiry: cert.days_until_expiry,
                is_expiring_soon: cert.days_until_expiry <= warn_days,
                san_domains: cert.matching_identities,
                certificate_url: cert.certificate_url
            })),
            
            // 监控状态
            status: {
                has_valid_cert: activeCerts.length > 0,
                expiring_soon: activeCerts.some(cert => cert.days_until_expiry <= warn_days),
                warnings: []
            }
        };

        // 生成警告信息
        if (activeCerts.length === 0) {
            monitor.status.warnings.push('未找到有效的SSL证书');
        }

        activeCerts.forEach(cert => {
            if (cert.days_until_expiry <= warn_days) {
                monitor.status.warnings.push(
                    `证书将在 ${cert.days_until_expiry} 天后过期 (${cert.not_after})`
                );
            }
            
            if (cert.days_until_expiry <= 0) {
                monitor.status.warnings.push('证书已过期');
            }
        });

        return monitor;

    } catch (error) {
        return {
            domain: domain,
            check_time: new Date().toISOString(),
            error: error.message,
            status: {
                has_valid_cert: false,
                expiring_soon: false,
                warnings: [`监控失败: ${error.message}`]
            }
        };
    }
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
                'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
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

// MCP 信息处理
function handleMCPInfo() {
    return new Response(JSON.stringify(MCP_SERVER_INFO), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

// MCP 工具列表处理
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

// MCP 资源列表处理
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

// MCP 资源内容处理
function handleMCPResource(resourceId) {
    let content = {};
    
    switch (resourceId) {
        case 'crt_api':
            content = {
                name: "Certificate Transparency API",
                description: "crt.sh provides access to Certificate Transparency logs",
                endpoints: {
                    search: "/?q={query}&output=json",
                    organization: "/?O={org}&output=json",
                    fingerprint: "/?sha1={fingerprint}&output=json"
                },
                rate_limits: "Please be respectful with API usage",
                documentation: "https://crt.sh/gen-add-chain"
            };
            break;
        case 'ca_list':
            content = {
                major_cas: Object.entries(CA_MAPPING).map(([short, full]) => ({
                    short_name: short,
                    full_name: full
                }))
            };
            break;
        default:
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

    return new Response(JSON.stringify(content), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

// MCP 工具调用处理
async function handleMCPToolCall(request) {
    try {
        const { tool, arguments: args } = await request.json();

        let result = null;

        switch (tool) {
            case 'cert_search':
                result = await queryCrtSh(args.query, {
                    type: args.type || 'domain',
                    limit: args.limit || 50,
                    include_expired: args.include_expired !== false,
                    format: args.format || 'detailed'
                });
                break;

            case 'cert_stats':
                result = await generateCertStats(args.query, args.days || 90);
                break;

            case 'cert_monitor':
                result = await monitorDomainCerts(args.domain, {
                    check_chain: args.check_chain !== false,
                    warn_days: args.warn_days || 30
                });
                break;

            default:
                return new Response(JSON.stringify({
                    error: "Unknown tool",
                    message: `Tool '${tool}' not found`
                }), {
                    status: 400,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
        }

        return new Response(JSON.stringify({
            tool: tool,
            result: result,
            success: true
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: "Tool execution failed",
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

// 处理 MCP SSE 连接
function handleMCPSSE(request) {
    // 对于 GET 请求，建立 SSE 连接
    if (request.method === 'GET') {
        // 创建初始化消息
        const initMessage = {
            jsonrpc: "2.0",
            id: null,
            method: "notifications/initialized",
            params: {
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
                    version: MCP_SERVER_INFO.version,
                    description: MCP_SERVER_INFO.description
                }
            }
        };
        
        // 创建 SSE 格式的响应
        const sseData = `data: ${JSON.stringify(initMessage)}\n\n`;
        
        return new Response(sseData, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, Accept, Authorization, X-Requested-With',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            }
        });
    }
    
    // 对于其他请求方法，返回错误
    return new Response(JSON.stringify({
        error: "Method not allowed",
        message: "Use GET for SSE connection or POST for messages"
    }), {
        status: 405,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, Accept, Authorization, X-Requested-With',
        }
    });
}

// 处理 MCP SSE 消息
async function handleMCPSSEMessage(request) {
    try {
        const data = await request.json();
        
        // 特殊处理初始化请求
        if (data.method === 'initialize') {
            const result = {
                jsonrpc: "2.0",
                id: data.id,
                result: {
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
                        version: MCP_SERVER_INFO.version,
                        description: MCP_SERVER_INFO.description
                    }
                }
            };
            
            return new Response(`data: ${JSON.stringify(result)}\n\n`, {
                headers: {
                    'Content-Type': 'text/event-stream',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, Accept, Authorization, X-Requested-With',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                }
            });
        }
        
        // 处理其他 MCP 消息
        const result = await processMCPMessage(data);

        return new Response(`data: ${JSON.stringify(result)}\n\n`, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, Accept, Authorization, X-Requested-With',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, Accept, Authorization, X-Requested-With',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            }
        });
    }
}

// 处理 MCP StreamableHttp 连接
function handleMCPStreamableHttp(request) {
    // 对于 GET 请求，返回连接确认
    if (request.method === 'GET') {
        return new Response('MCP StreamableHttp endpoint ready', {
            status: 200,
            headers: {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
                'Access-Control-Max-Age': '86400',
            }
        });
    }
    
    // 对于其他请求，返回错误
    return new Response(JSON.stringify({
        error: "Method not allowed",
        message: "Use POST for MCP messages"
    }), {
        status: 405,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
        }
    });
}

// 处理 MCP StreamableHttp 消息
async function handleMCPStreamableHttpMessage(request) {
    try {
        const data = await request.json();
        
        // 特殊处理初始化请求
        if (data.method === 'initialize') {
            const result = {
                jsonrpc: "2.0",
                id: data.id,
                result: {
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
                        },
                        experimental: {
                            streamableHttp: {}
                        }
                    },
                    serverInfo: {
                        name: MCP_SERVER_INFO.name,
                        version: MCP_SERVER_INFO.version,
                        description: MCP_SERVER_INFO.description
                    }
                }
            };
            
            return new Response(JSON.stringify(result), {
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
                }
            });
        }
        
        // 处理其他 MCP 消息
        const result = await processMCPMessage(data);

        return new Response(JSON.stringify(result), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
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
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
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
            try {
                if (toolName === 'cert_search') {
                    result = {
                        content: [{
                            type: "text",
                            text: JSON.stringify(await queryCrtSh(toolArgs.query, {
                                type: toolArgs.type || 'domain',
                                limit: toolArgs.limit || 50,
                                include_expired: toolArgs.include_expired !== false,
                                format: toolArgs.format || 'detailed'
                            }), null, 2)
                        }]
                    };
                } else if (toolName === 'cert_stats') {
                    result = {
                        content: [{
                            type: "text",
                            text: JSON.stringify(await generateCertStats(toolArgs.query, toolArgs.days || 90), null, 2)
                        }]
                    };
                } else if (toolName === 'cert_monitor') {
                    result = {
                        content: [{
                            type: "text",
                            text: JSON.stringify(await monitorDomainCerts(toolArgs.domain, {
                                check_chain: toolArgs.check_chain !== false,
                                warn_days: toolArgs.warn_days || 30
                            }), null, 2)
                        }]
                    };
                } else {
                    error = {
                        code: -32601,
                        message: "Method not found",
                        data: `Unknown tool: ${toolName}`
                    };
                }
            } catch (e) {
                error = {
                    code: -32603,
                    message: "Internal error",
                    data: e.message
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
            
            try {
                let content = {};
                
                switch (resourceId) {
                    case 'info':
                        content = {
                            name: "Certificate Transparency API",
                            description: "crt.sh provides access to Certificate Transparency logs",
                            endpoints: {
                                search: "/?q={query}&output=json",
                                organization: "/?O={org}&output=json",
                                fingerprint: "/?sha1={fingerprint}&output=json"
                            }
                        };
                        break;
                    case 'list':
                        content = {
                            major_cas: Object.entries(CA_MAPPING).map(([short, full]) => ({
                                short_name: short,
                                full_name: full
                            }))
                        };
                        break;
                    default:
                        error = {
                            code: -32602,
                            message: "Invalid params",
                            data: `Unknown resource: ${resourceId}`
                        };
                }

                if (!error) {
                    result = {
                        contents: [{
                            uri: uri,
                            mimeType: "application/json",
                            text: JSON.stringify(content, null, 2)
                        }]
                    };
                }
            } catch (e) {
                error = {
                    code: -32603,
                    message: "Internal error",
                    data: e.message
                };
            }
            break;

        default:
            error = {
                code: -32601,
                message: "Method not found",
                data: `Unknown method: ${method}`
            };
    }

    if (error) {
        return {
            jsonrpc: "2.0",
            id: id,
            error: error
        };
    } else {
        return {
            jsonrpc: "2.0",
            id: id,
            result: result
        };
    }
}

// 主要的 Worker 入口点
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 处理CORS预检请求
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-Requested-With',
                    'Access-Control-Max-Age': '86400',
                }
            });
        }

        // 根路径返回使用说明
        if (url.pathname === '/') {
            return new Response(`
Certificate Search Service + MCP Server

=== Certificate Search API ===
使用方法:
GET  /search?q=example.com&type=domain&limit=50
POST /search (JSON body)

支持的查询类型: domain, organization, fingerprint, serial

示例:
- /search?q=google.com&type=domain
- /search?q=Google%20Inc&type=organization
- /search?q=*.cloudflare.com&type=domain

参数:
- q: 查询内容 (必需)
- type: 查询类型 (默认: domain)
- limit: 结果数量限制 (默认: 50)
- include_expired: 是否包含过期证书 (默认: true)
- format: 返回格式 summary/detailed/raw (默认: detailed)

=== Certificate Statistics API ===
GET  /stats?q=example.com&days=90

返回域名或组织的证书统计信息，包括CA分布、颁发趋势等。

=== Certificate Monitoring API ===
GET  /monitor?domain=example.com&warn_days=30

监控域名证书状态，检查到期时间和配置。

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
- cert_search: 搜索SSL/TLS证书
- cert_stats: 获取证书统计信息  
- cert_monitor: 监控域名证书状态

MCP使用示例:
curl -X POST /mcp/tools/call \\
-H "Content-Type: application/json" \\
-d '{"tool": "cert_search", "arguments": {"query": "example.com", "type": "domain"}}'

特性:
- 基于 crt.sh Certificate Transparency 数据库
- 支持多种查询类型和格式
- 提供详细的证书统计分析
- 证书到期监控和预警
- 完整的MCP协议支持

数据来源: Certificate Transparency logs via crt.sh
    `, {
                headers: {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        // 处理证书搜索
        if (url.pathname === '/search') {
            try {
                let query, type, limit, include_expired, format;

                if (request.method === 'GET') {
                    query = url.searchParams.get('q');
                    type = url.searchParams.get('type') || 'domain';
                    limit = parseInt(url.searchParams.get('limit')) || 50;
                    include_expired = url.searchParams.get('include_expired') !== 'false';
                    format = url.searchParams.get('format') || 'detailed';

                    if (!query) {
                        return new Response(JSON.stringify({
                            error: '缺少查询参数 q'
                        }), {
                            status: 400,
                            headers: {
                                'Content-Type': 'application/json',
                                'Access-Control-Allow-Origin': '*'
                            }
                        });
                    }
                } else if (request.method === 'POST') {
                    const body = await request.json();
                    query = body.query;
                    type = body.type || 'domain';
                    limit = body.limit || 50;
                    include_expired = body.include_expired !== false;
                    format = body.format || 'detailed';

                    if (!query) {
                        return new Response(JSON.stringify({
                            error: '缺少查询参数 query'
                        }), {
                            status: 400,
                            headers: {
                                'Content-Type': 'application/json',
                                'Access-Control-Allow-Origin': '*'
                            }
                        });
                    }
                } else {
                    return new Response('Method not allowed', { status: 405 });
                }

                const results = await queryCrtSh(query, {
                    type,
                    limit,
                    include_expired,
                    format
                });

                return new Response(JSON.stringify({
                    query: query,
                    type: type,
                    results: results,
                    count: results.length
                }), {
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });

            } catch (error) {
                return new Response(JSON.stringify({
                    error: error.message
                }), {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }

        // 处理证书统计
        if (url.pathname === '/stats') {
            try {
                const query = url.searchParams.get('q');
                const days = parseInt(url.searchParams.get('days')) || 90;

                if (!query) {
                    return new Response(JSON.stringify({
                        error: '缺少查询参数 q'
                    }), {
                        status: 400,
                        headers: {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }

                const stats = await generateCertStats(query, days);

                return new Response(JSON.stringify(stats), {
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });

            } catch (error) {
                return new Response(JSON.stringify({
                    error: error.message
                }), {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }

        // 处理证书监控
        if (url.pathname === '/monitor') {
            try {
                const domain = url.searchParams.get('domain');
                const warn_days = parseInt(url.searchParams.get('warn_days')) || 30;
                const check_chain = url.searchParams.get('check_chain') !== 'false';

                if (!domain) {
                    return new Response(JSON.stringify({
                        error: '缺少域名参数 domain'
                    }), {
                        status: 400,
                        headers: {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }

                const monitor = await monitorDomainCerts(domain, {
                    check_chain,
                    warn_days
                });

                return new Response(JSON.stringify(monitor), {
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });

            } catch (error) {
                return new Response(JSON.stringify({
                    error: error.message
                }), {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }

        // 处理MCP请求
        if (url.pathname.startsWith('/mcp')) {
            return handleMCPRequest(request, url);
        }

        // 404 页面
        return new Response('Not Found', {
            status: 404,
            headers: {
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
};
