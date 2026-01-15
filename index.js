import { generatePKCE } from "@openauthjs/openauth/pkce";

// ============================================================================
// Constants
// ============================================================================

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const BASE_FETCH = globalThis.fetch?.bind(globalThis);
const FETCH_PATCH_STATE = {
    installed: false,
    getAuth: null,
    client: null,
};

const MODEL_ID_OVERRIDES = new Map([
    ["claude-sonnet-4-5", "claude-sonnet-4-5-20250929"],
    ["claude-opus-4-5", "claude-opus-4-5-20251101"],
    ["claude-haiku-4-5", "claude-haiku-4-5-20251001"],
]);
const MODEL_ID_REVERSE_OVERRIDES = new Map(
    Array.from(MODEL_ID_OVERRIDES, ([base, full]) => [full, base])
);

// Tool name mappings: OpenCode snake_case → Claude PascalCase
const OPENCODE_TO_CLAUDE_TOOLS = new Map([
    ["bash", "Bash"],
    ["read", "Read"],
    ["edit", "Edit"],
    ["write", "Write"],
    ["task", "Task"],
    ["glob", "Glob"],
    ["grep", "Grep"],
    ["webfetch", "WebFetch"],
    ["websearch", "WebSearch"],
    ["todowrite", "TodoWrite"],
    ["todoread", "Todoread"],
    ["question", "AskUserQuestion"],
]);

// Reverse: Claude PascalCase → OpenCode snake_case
const CLAUDE_TO_OPENCODE_TOOLS = new Map(
    Array.from(OPENCODE_TO_CLAUDE_TOOLS, ([oc, claude]) => [claude, oc])
);

// Parameter name mappings: snake_case (Claude) ↔ camelCase (OpenCode)
const SNAKE_TO_CAMEL_PARAMS = new Map([
    ["file_path", "filePath"],
    ["old_string", "oldString"],
    ["new_string", "newString"],
    ["replace_all", "replaceAll"],
    ["work_dir", "workDir"],
    ["session_id", "sessionId"],
    ["subagent_type", "subagentType"],
    ["timeout_ms", "timeoutMs"],
    ["max_tokens", "maxTokens"],
    ["stop_sequences", "stopSequences"],
    ["tool_choice", "toolChoice"],
    ["input_schema", "inputSchema"],
    ["cache_control", "cacheControl"],
    ["user_id", "userId"],
    ["api_key", "apiKey"],
]);

const CAMEL_TO_SNAKE_PARAMS = new Map(
    Array.from(SNAKE_TO_CAMEL_PARAMS, ([snake, camel]) => [camel, snake])
);

let cachedMetadataUserIdPromise;
let tokenRefreshPromise = null;

// ============================================================================
// Debug Logging
// ============================================================================

function debugLog(context, data) {
    if (globalThis.process?.env?.OPENCODE_DEBUG === "true") {
        console.debug(`[opencode-anthropic-auth] ${context}:`, data);
    }
}

// File logging for debugging (doesn't mess up terminal UI)
let debugFileHandle = null;
let errorFileHandle = null;
let logsDir = null;

async function initLogsDir() {
    if (logsDir) return logsDir;
    const { fileURLToPath } = await import("node:url");
    const path = await import("node:path");
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    logsDir = path.join(__dirname, "logs");
    return logsDir;
}

async function forceLog(context, data) {
    try {
        if (!debugFileHandle) {
            const fs = await import("node:fs/promises");
            const path = await import("node:path");
            const dir = await initLogsDir();
            const logPath = path.join(dir, "debug.log");
            debugFileHandle = await fs.open(logPath, "a");
        }
        const timestamp = new Date().toISOString();
        const msg = `${timestamp} [${context}]: ${JSON.stringify(data).slice(0, 1000)}\n`;
        await debugFileHandle.write(msg);
    } catch {
        // Ignore logging errors
    }
}

async function errorLog(context, data) {
    try {
        if (!errorFileHandle) {
            const fs = await import("node:fs/promises");
            const path = await import("node:path");
            const dir = await initLogsDir();
            const logPath = path.join(dir, "error.log");
            errorFileHandle = await fs.open(logPath, "a");
        }
        const timestamp = new Date().toISOString();
        const msg = `${timestamp} [${context}]: ${JSON.stringify(data).slice(0, 1000)}\n`;
        await errorFileHandle.write(msg);
    } catch {
        // Ignore logging errors
    }
}

// ============================================================================
// Case Conversion Utilities
// ============================================================================

function toCamelCase(str) {
    if (!str) return str;
    // Check hardcoded mapping first
    if (SNAKE_TO_CAMEL_PARAMS.has(str)) {
        return SNAKE_TO_CAMEL_PARAMS.get(str);
    }
    // Algorithmic: file_path → filePath
    return str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
}

function toSnakeCase(str) {
    if (!str) return str;
    // Check hardcoded mapping first
    if (CAMEL_TO_SNAKE_PARAMS.has(str)) {
        return CAMEL_TO_SNAKE_PARAMS.get(str);
    }
    // Algorithmic: filePath → file_path
    return str.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function toPascalCase(str) {
    if (!str) return str;
    return str
        .replace(/[^a-zA-Z0-9]+/g, " ")
        .split(" ")
        .filter(Boolean)
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join("");
}

function stripToolPrefix(name) {
    if (!name) return name;
    return name.replace(/^(?:oc_|mcp_)/i, "");
}

// ============================================================================
// Tool Name Conversion
// ============================================================================

function toClaudeToolName(name) {
    if (!name) return name;
    const stripped = stripToolPrefix(name);
    const mapped = OPENCODE_TO_CLAUDE_TOOLS.get(stripped.toLowerCase());
    return mapped ?? toPascalCase(stripped);
}

function toOpenCodeToolName(name) {
    if (!name) return name;
    const mapped = CLAUDE_TO_OPENCODE_TOOLS.get(name);
    return mapped ?? toSnakeCase(name);
}

// ============================================================================
// Object Key Conversion
// ============================================================================

function convertKeysToSnakeCase(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(convertKeysToSnakeCase);

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        const snakeKey = toSnakeCase(key);
        result[snakeKey] = convertKeysToSnakeCase(value);
    }
    return result;
}

function convertKeysToCamelCase(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(convertKeysToCamelCase);

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        const camelKey = toCamelCase(key);
        result[camelKey] = convertKeysToCamelCase(value);
    }
    return result;
}

// ============================================================================
// Environment & Headers
// ============================================================================

function getEnvConfig() {
    const env = globalThis.process?.env ?? {};
    const platform = globalThis.process?.platform ?? "linux";
    const os =
        env.OPENCODE_STAINLESS_OS ??
        (platform === "darwin"
            ? "Darwin"
            : platform === "win32"
                ? "Windows"
                : platform === "linux"
                    ? "Linux"
                    : platform);

    return {
        os,
        arch: env.OPENCODE_STAINLESS_ARCH ?? globalThis.process?.arch ?? "x64",
        lang: env.OPENCODE_STAINLESS_LANG ?? "js",
        packageVersion: env.OPENCODE_STAINLESS_PACKAGE_VERSION ?? "0.70.0",
        runtime: env.OPENCODE_STAINLESS_RUNTIME ?? "node",
        runtimeVersion:
            env.OPENCODE_STAINLESS_RUNTIME_VERSION ??
            globalThis.process?.version ??
            "v24.3.0",
        retryCount: env.OPENCODE_STAINLESS_RETRY_COUNT ?? "0",
        timeout: env.OPENCODE_STAINLESS_TIMEOUT ?? "600",
    };
}

function applyStainlessHeaders(headers, isStream = false) {
    const config = getEnvConfig();

    headers.set("accept", "application/json");
    headers.set("user-agent", "claude-cli/2.1.7 (external, cli)");
    headers.set("x-app", "cli");
    headers.set("anthropic-dangerous-direct-browser-access", "true");
    headers.set("x-stainless-arch", config.arch);
    headers.set("x-stainless-lang", config.lang);
    headers.set("x-stainless-os", config.os);
    headers.set("x-stainless-package-version", config.packageVersion);
    headers.set("x-stainless-runtime", config.runtime);
    headers.set("x-stainless-runtime-version", config.runtimeVersion);
    headers.set("x-stainless-retry-count", config.retryCount);
    headers.set("x-stainless-timeout", config.timeout);

    if (isStream) {
        headers.set("x-stainless-helper-method", "stream");
    }
}

function getBetaHeadersForPath(pathname, hasTools = false) {
    if (pathname === "/v1/messages") {
        if (hasTools) {
            return [
                "claude-code-20250219",
                "oauth-2025-04-20",
                "interleaved-thinking-2025-05-14",
            ];
        }
        return ["oauth-2025-04-20", "interleaved-thinking-2025-05-14"];
    }
    if (pathname === "/v1/messages/count_tokens") {
        return [
            "claude-code-20250219",
            "oauth-2025-04-20",
            "interleaved-thinking-2025-05-14",
            "token-counting-2024-11-01",
        ];
    }
    if (pathname.startsWith("/api/") && pathname !== "/api/hello") {
        return ["oauth-2025-04-20"];
    }
    return [];
}

function mergeHeaders(request, init) {
    const headers = new Headers();

    if (request instanceof Request) {
        request.headers.forEach((value, key) => headers.set(key, value));
    }

    const initHeaders = init?.headers;
    if (initHeaders) {
        if (initHeaders instanceof Headers) {
            initHeaders.forEach((value, key) => headers.set(key, value));
        } else if (Array.isArray(initHeaders)) {
            for (const [key, value] of initHeaders) {
                if (value !== undefined) headers.set(key, String(value));
            }
        } else {
            for (const [key, value] of Object.entries(initHeaders)) {
                if (value !== undefined) headers.set(key, String(value));
            }
        }
    }

    return headers;
}

function extractUrl(input) {
    try {
        if (typeof input === "string" || input instanceof URL) {
            return new URL(input.toString());
        }
        if (input instanceof Request) {
            return new URL(input.url);
        }
    } catch (error) {
        debugLog("extractUrl", error);
    }
    return null;
}

function getBaseFetch() {
    return BASE_FETCH ?? globalThis.fetch;
}

// ============================================================================
// Request Transformation (OpenCode → Claude)
// ============================================================================

function sanitizeDescription(description) {
    if (!description || typeof description !== "string") return description;
    return description
        .replace(/\/(?:home|Users|tmp|var|opt|usr|etc)\/[^\s,)"'\]]+/g, "[path]")
        .replace(/[A-Z]:\\[^\s,)"'\]]+/gi, "[path]")
        .replace(/opencode/gi, "Claude")
        .replace(/OpenCode/g, "Claude Code");
}

function normalizeToolForClaude(tool) {
    if (!tool || typeof tool !== "object") return tool;

    const normalized = { ...tool };

    if (normalized.name) {
        normalized.name = toClaudeToolName(normalized.name);
    }

    if (normalized.description) {
        normalized.description = sanitizeDescription(normalized.description);
    }

    // DON'T convert parameter names to snake_case
    // Keep OpenCode's original camelCase so Claude responds with camelCase
    // This avoids the impossible task of transforming split partial_json chunks

    return normalized;
}

function normalizeToolsForClaude(tools) {
    if (!Array.isArray(tools)) return [];
    return tools.map(normalizeToolForClaude);
}

function normalizeMessagesForClaude(messages) {
    if (!Array.isArray(messages)) return messages;
    return messages.map((message) => {
        if (!message || !Array.isArray(message.content)) return message;
        return {
            ...message,
            content: message.content.map((block) => {
                if (block?.type === "tool_use") {
                    const normalized = { ...block };
                    // Convert tool name: read → Read
                    if (normalized.name) {
                        normalized.name = toClaudeToolName(normalized.name);
                    }
                    // DON'T convert input keys - keep OpenCode's camelCase
                    return normalized;
                }
                if (block?.type === "tool_result" && block.tool_use_id) {
                    return block; // tool_result doesn't need transformation
                }
                return block;
            }),
        };
    });
}

function stripCacheControlFromSystem(system) {
    if (!Array.isArray(system)) return system;
    return system.map((block) => {
        if (block && typeof block === "object" && "cache_control" in block) {
            const { cache_control, ...rest } = block;
            return rest;
        }
        return block;
    });
}

function normalizeModelId(id) {
    if (!id) return id;
    return MODEL_ID_OVERRIDES.get(id) ?? id;
}

async function normalizeRequestBody(parsed, injectMetadata = false) {
    // Sanitize system prompt
    if (Array.isArray(parsed.system)) {
        parsed.system = parsed.system.map((item) => {
            if (item.type === "text" && item.text) {
                return {
                    ...item,
                    text: item.text
                        .replace(/OpenCode/g, "Claude Code")
                        .replace(/opencode/gi, "Claude"),
                };
            }
            return item;
        });
        parsed.system = stripCacheControlFromSystem(parsed.system);
    }

    // Normalize model
    if (parsed.model) {
        parsed.model = normalizeModelId(parsed.model);
    }

    // Normalize tools
    parsed.tools = normalizeToolsForClaude(parsed.tools);

    // Normalize messages
    if (Array.isArray(parsed.messages)) {
        parsed.messages = normalizeMessagesForClaude(parsed.messages);
    }

    // Remove unsupported fields
    delete parsed.temperature;
    delete parsed.tool_choice;

    // Inject metadata
    if (injectMetadata) {
        const userId = await resolveMetadataUserId();
        if (userId) {
            parsed.metadata = { ...(parsed.metadata ?? {}), user_id: userId };
        }
    }

    return { body: parsed, isStream: !!parsed.stream };
}

// ============================================================================
// Response Transformation (Claude → OpenCode)
// ============================================================================

function transformJsonString(str) {
    if (typeof str !== "string") return str;

    let result = str;

    // Replace known snake_case params with their camelCase equivalents (only keys, not values)
    // The lookahead (?=\s*:) ensures we only match JSON keys
    for (const [snake, camel] of SNAKE_TO_CAMEL_PARAMS) {
        result = result.replace(
            new RegExp(`"${snake}"(?=\\s*:)`, "g"),
            `"${camel}"`
        );
    }

    // Generic snake_case to camelCase conversion for any remaining JSON keys
    // Matches "key_name": patterns and converts to "keyName":
    result = result.replace(/"([a-z]+(?:_[a-z0-9]+)+)"(?=\s*:)/g, (match, key) => {
        const camelKey = key.replace(/_([a-z0-9])/g, (_, char) =>
            char.toUpperCase()
        );
        return `"${camelKey}"`;
    });

    return result;
}

function transformResponseJson(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(transformResponseJson);

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        let newValue = value;

        // Convert tool name: Read → read
        if (key === "name" && typeof value === "string") {
            newValue = toOpenCodeToolName(value);
        }
        // DON'T convert input keys - Claude now uses camelCase (matching OpenCode's schema)
        // Convert model ID back
        else if (key === "model" && typeof value === "string") {
            newValue = MODEL_ID_REVERSE_OVERRIDES.get(value) ?? value;
        }
        // Recursively transform nested objects (for tool name conversion in nested structures)
        else if (typeof value === "object") {
            newValue = transformResponseJson(value);
        }

        result[key] = newValue;
    }
    return result;
}

function transformSseLine(line) {
    if (!line.startsWith("data: ")) return line;

    const jsonStr = line.slice(6);
    if (!jsonStr || jsonStr === "[DONE]") return line;

    try {
        const parsed = JSON.parse(jsonStr);

        // Log tool-related events
        if (parsed.type === "content_block_start" && parsed.content_block?.type === "tool_use") {
            forceLog("SSE.tool_use.start", { name: parsed.content_block.name });
        }
        if (parsed.type === "content_block_delta" && parsed.delta?.partial_json) {
            forceLog("SSE.partial_json", parsed.delta.partial_json.slice(0, 200));
        }

        // Only transform tool names (Read → read), NOT parameter keys
        const transformed = transformResponseJson(parsed);
        return "data: " + JSON.stringify(transformed);
    } catch {
        // Partial JSON - pass through unchanged (can't transform split keys)
        return line;
    }
}

function transformSseText(text) {
    const lines = text.split("\n");
    return lines.map(transformSseLine).join("\n");
}

function transformPlainJson(text) {
    try {
        const parsed = JSON.parse(text);
        return JSON.stringify(transformResponseJson(parsed));
    } catch {
        // If parsing fails, try string-based transformation
        return transformJsonString(text);
    }
}

function createTransformedResponse(response) {
    if (!response.body) return response;

    const contentType = response.headers.get("content-type") ?? "";
    const isStreaming = contentType.includes("text/event-stream");
    const isJson = contentType.includes("application/json");

    forceLog("createTransformedResponse.CALLED", { contentType, isStreaming, isJson });
    debugLog("createTransformedResponse", { contentType, isStreaming, isJson });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    let buffer = "";

    const stream = new ReadableStream({
        async pull(controller) {
            const { done, value } = await reader.read();

            if (done) {
                // Flush remaining buffer
                const flushed = decoder.decode(new Uint8Array(), { stream: false });
                if (flushed) buffer += flushed;

                if (buffer.length > 0) {
                    let transformed;
                    if (isJson) {
                        // Non-streaming JSON response
                        transformed = transformPlainJson(buffer);
                    } else {
                        // SSE or unknown - try SSE transformation
                        transformed = transformSseText(buffer);
                    }
                    debugLog("finalBuffer", { original: buffer.slice(0, 200), transformed: transformed.slice(0, 200) });
                    controller.enqueue(encoder.encode(transformed));
                }
                controller.close();
                return;
            }

            buffer += decoder.decode(value, { stream: true });

            if (isStreaming) {
                // SSE: Process complete events (separated by double newlines)
                const events = buffer.split("\n\n");
                buffer = events.pop() ?? "";

                if (events.length > 0) {
                    const completeData = events.join("\n\n") + "\n\n";
                    const transformed = transformSseText(completeData);
                    controller.enqueue(encoder.encode(transformed));
                }
            } else if (isJson) {
                // Non-streaming JSON: Wait for complete response (handled in done block)
                // Don't emit partial data
            } else {
                // Unknown content type - try to detect
                const trimmed = buffer.trim();
                if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                    // Looks like JSON - wait for complete response
                } else if (trimmed.includes("data: ")) {
                    // Looks like SSE - process as SSE
                    const events = buffer.split("\n\n");
                    buffer = events.pop() ?? "";

                    if (events.length > 0) {
                        const completeData = events.join("\n\n") + "\n\n";
                        const transformed = transformSseText(completeData);
                        controller.enqueue(encoder.encode(transformed));
                    }
                }
            }
        },
    });

    return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
    });
}

// ============================================================================
// OAuth Token Management
// ============================================================================

async function resolveMetadataUserId() {
    const env = globalThis.process?.env ?? {};
    const direct =
        env.OPENCODE_ANTHROPIC_USER_ID ??
        env.CLAUDE_CODE_USER_ID ??
        env.ANTHROPIC_USER_ID;
    if (direct) return direct;
    if (cachedMetadataUserIdPromise) return cachedMetadataUserIdPromise;

    cachedMetadataUserIdPromise = (async () => {
        const home = env.HOME ?? env.USERPROFILE;
        if (!home) return undefined;

        try {
            const { readFile } = await import("node:fs/promises");
            const data = JSON.parse(
                await readFile(
                    env.OPENCODE_CLAUDE_CONFIG ?? `${home}/.claude.json`,
                    "utf8"
                )
            );
            const userId = data?.userID;
            const accountUuid = data?.oauthAccount?.accountUuid;

            let sessionId;
            const cwd = globalThis.process?.cwd?.();
            if (cwd && data?.projects?.[cwd]?.lastSessionId) {
                sessionId = data.projects[cwd].lastSessionId;
            } else if (data?.projects) {
                for (const project of Object.values(data.projects)) {
                    if (project?.lastSessionId) {
                        sessionId = project.lastSessionId;
                        break;
                    }
                }
            }

            if (userId && accountUuid && sessionId) {
                return `user_${userId}_account_${accountUuid}_session_${sessionId}`;
            }
        } catch (error) {
            debugLog("resolveMetadataUserId", error);
        }
        return undefined;
    })();

    return cachedMetadataUserIdPromise;
}

async function refreshOAuthToken(auth, baseFetch) {
    const response = await baseFetch(
        "https://console.anthropic.com/v1/oauth/token",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                grant_type: "refresh_token",
                refresh_token: auth.refresh,
                client_id: CLIENT_ID,
            }),
        }
    );
    if (!response.ok) throw new Error(`Token refresh failed: ${response.status}`);
    return response.json();
}

async function ensureOAuthAccess(getAuth, client) {
    if (!getAuth) return null;
    const auth = await getAuth();
    if (!auth || auth.type !== "oauth") return auth ?? null;
    if (auth.access && auth.expires > Date.now()) return auth;

    const json = await refreshOAuthToken(auth, getBaseFetch());
    const newExpires = Date.now() + json.expires_in * 1000;

    if (client?.auth?.set) {
        await client.auth.set({
            path: { id: "anthropic" },
            body: {
                type: "oauth",
                refresh: json.refresh_token,
                access: json.access_token,
                expires: newExpires,
            },
        });
    }

    auth.refresh = json.refresh_token;
    auth.access = json.access_token;
    auth.expires = newExpires;
    return auth;
}

// ============================================================================
// Anthropic Request Handler
// ============================================================================

async function handleAnthropicRequest(input, init, auth, baseFetch) {
    const requestUrl = extractUrl(input);

    forceLog("handleAnthropicRequest.CALLED", { url: requestUrl?.pathname, hasAuth: !!auth });
    debugLog("handleAnthropicRequest.start", { url: requestUrl?.pathname });

    if (!requestUrl) {
        debugLog("handleAnthropicRequest", "Failed to extract URL");
        return baseFetch(input, init);
    }

    const requestHeaders = mergeHeaders(
        input instanceof Request ? input : null,
        init
    );

    requestHeaders.set("authorization", `Bearer ${auth.access}`);
    requestHeaders.delete("x-api-key");

    const requestInit = init ?? {};
    let body = requestInit.body;

    if (!body && input instanceof Request) {
        try {
            body = await input.clone().text();
        } catch (error) {
            debugLog("handleAnthropicRequest.cloneBody", error);
            body = requestInit.body;
        }
    }

    let isStream = false;
    let hasTools = false;

    if (body && typeof body === "string") {
        try {
            const parsed = JSON.parse(body);
            hasTools = Array.isArray(parsed.tools) && parsed.tools.length > 0;
            const result = await normalizeRequestBody(
                parsed,
                requestUrl.pathname === "/v1/messages"
            );
            body = JSON.stringify(result.body);
            isStream = result.isStream;
        } catch (error) {
            debugLog("handleAnthropicRequest.normalizeBody", error);
        }
    }

    const betaHeaders = getBetaHeadersForPath(requestUrl.pathname, hasTools);
    if (betaHeaders.length > 0) {
        requestHeaders.set("anthropic-beta", betaHeaders.join(","));
    } else {
        requestHeaders.delete("anthropic-beta");
    }

    applyStainlessHeaders(requestHeaders, isStream);

    if (
        (requestUrl.pathname === "/v1/messages" ||
            requestUrl.pathname === "/v1/messages/count_tokens") &&
        !requestUrl.searchParams.has("beta")
    ) {
        requestUrl.searchParams.set("beta", "true");
    }

    let requestInput = requestUrl;
    let requestInitOut = { ...requestInit, headers: requestHeaders, body };

    if (input instanceof Request) {
        requestInput = new Request(requestUrl.toString(), {
            ...requestInit,
            headers: requestHeaders,
            body,
        });
        requestInitOut = undefined;
    }

    const response = await baseFetch(requestInput, requestInitOut);
    return createTransformedResponse(response);
}

// ============================================================================
// Global Fetch Patch
// ============================================================================

function installAnthropicFetchPatch(getAuth, client) {
    if (FETCH_PATCH_STATE.installed) {
        if (getAuth) FETCH_PATCH_STATE.getAuth = getAuth;
        if (client) FETCH_PATCH_STATE.client = client;
        return;
    }
    if (!globalThis.fetch) return;

    FETCH_PATCH_STATE.installed = true;
    FETCH_PATCH_STATE.getAuth = getAuth ?? null;
    FETCH_PATCH_STATE.client = client ?? null;

    const baseFetch = getBaseFetch();

    const patchedFetch = async (input, init) => {
        const requestUrl = extractUrl(input);

        if (!requestUrl || requestUrl.hostname !== "api.anthropic.com") {
            return baseFetch(input, init);
        }

        let auth = null;
        try {
            auth = await ensureOAuthAccess(
                FETCH_PATCH_STATE.getAuth,
                FETCH_PATCH_STATE.client
            );
        } catch (error) {
            debugLog("patchedFetch.ensureOAuthAccess", error);
            auth = null;
        }

        const requestHeaders = mergeHeaders(
            input instanceof Request ? input : null,
            init
        );
        const authorization = requestHeaders.get("authorization") ?? "";
        const shouldPatch =
            auth?.type === "oauth" || authorization.includes("sk-ant-oat");

        if (!shouldPatch) {
            return baseFetch(input, init);
        }

        return handleAnthropicRequest(input, init, auth, baseFetch);
    };

    patchedFetch.__opencodeAnthropicPatched = true;
    globalThis.fetch = patchedFetch;
}

// ============================================================================
// OAuth Flow
// ============================================================================

async function authorize(mode) {
    const pkce = await generatePKCE();
    const url = new URL(
        `https://${mode === "console" ? "console.anthropic.com" : "claude.ai"}/oauth/authorize`,
        import.meta.url
    );

    url.searchParams.set("code", "true");
    url.searchParams.set("client_id", CLIENT_ID);
    url.searchParams.set("response_type", "code");
    url.searchParams.set(
        "redirect_uri",
        "https://console.anthropic.com/oauth/code/callback"
    );
    url.searchParams.set(
        "scope",
        "org:create_api_key user:profile user:inference user:sessions:claude_code"
    );
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", pkce.verifier);

    return { url: url.toString(), verifier: pkce.verifier };
}

async function exchange(code, verifier) {
    const hashIndex = code.indexOf("#");
    const authCode = hashIndex >= 0 ? code.slice(0, hashIndex) : code;
    const state = hashIndex >= 0 ? code.slice(hashIndex + 1) : undefined;

    const baseFetch = getBaseFetch();
    const result = await baseFetch(
        "https://console.anthropic.com/v1/oauth/token",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: authCode,
                state,
                grant_type: "authorization_code",
                client_id: CLIENT_ID,
                redirect_uri: "https://console.anthropic.com/oauth/code/callback",
                code_verifier: verifier,
            }),
        }
    );

    if (!result.ok) return { type: "failed" };

    const json = await result.json();
    return {
        type: "success",
        refresh: json.refresh_token,
        access: json.access_token,
        expires: Date.now() + json.expires_in * 1000,
    };
}

// ============================================================================
// Plugin Export
// ============================================================================

/** @type {import('@opencode-ai/plugin').Plugin} */
export async function AnthropicAuthPlugin({ client }) {
    forceLog("AnthropicAuthPlugin.LOADED", { hasClient: !!client });

    return {
        auth: {
            provider: "anthropic",

            async loader(getAuth, provider) {
                const auth = await getAuth();
                forceLog("auth.loader.CALLED", { authType: auth?.type });

                if (auth.type === "oauth") {
                    installAnthropicFetchPatch(getAuth, client);

                    for (const model of Object.values(provider.models)) {
                        model.cost = {
                            input: 0,
                            output: 0,
                            cache: { read: 0, write: 0 },
                        };
                    }

                    return {
                        apiKey: "",
                        async fetch(input, init) {
                            forceLog("plugin.fetch.CALLED", { url: extractUrl(input)?.pathname });
                            const auth = await getAuth();
                            if (auth.type !== "oauth") return fetch(input, init);

                            const baseFetch = getBaseFetch();

                            if (!auth.access || auth.expires < Date.now()) {
                                if (!tokenRefreshPromise) {
                                    tokenRefreshPromise = (async () => {
                                        try {
                                            const json = await refreshOAuthToken(auth, baseFetch);
                                            const newExpires = Date.now() + json.expires_in * 1000;
                                            await client.auth.set({
                                                path: { id: "anthropic" },
                                                body: {
                                                    type: "oauth",
                                                    refresh: json.refresh_token,
                                                    access: json.access_token,
                                                    expires: newExpires,
                                                },
                                            });
                                            auth.access = json.access_token;
                                            auth.expires = newExpires;
                                            return json;
                                        } finally {
                                            tokenRefreshPromise = null;
                                        }
                                    })();
                                }
                                await tokenRefreshPromise;
                            }

                            return handleAnthropicRequest(input, init, auth, baseFetch);
                        },
                    };
                }

                return {};
            },

            methods: [
                {
                    label: "Claude Pro/Max",
                    type: "oauth",
                    authorize: async () => {
                        const { url, verifier } = await authorize("max");
                        return {
                            url,
                            instructions: "Paste the authorization code here: ",
                            method: "code",
                            callback: (code) => exchange(code, verifier),
                        };
                    },
                },
                {
                    label: "Create an API Key",
                    type: "oauth",
                    authorize: async () => {
                        const { url, verifier } = await authorize("console");
                        return {
                            url,
                            instructions: "Paste the authorization code here: ",
                            method: "code",
                            callback: async (code) => {
                                const credentials = await exchange(code, verifier);
                                if (credentials.type === "failed") return credentials;

                                const baseFetch = getBaseFetch();
                                const result = await baseFetch(
                                    "https://api.anthropic.com/api/oauth/claude_cli/create_api_key",
                                    {
                                        method: "POST",
                                        headers: {
                                            "Content-Type": "application/json",
                                            authorization: `Bearer ${credentials.access}`,
                                        },
                                    }
                                ).then((r) => r.json());

                                return { type: "success", key: result.raw_key };
                            },
                        };
                    },
                },
                {
                    provider: "anthropic",
                    label: "Manually enter API Key",
                    type: "api",
                },
            ],
        },

        async "chat.params"(input, output) {
            const providerId = input.provider?.id ?? "";
            if (providerId && !providerId.includes("anthropic")) return;

            const options = output.options ?? {};
            output.options = options;

            const hasTools = Array.isArray(options.tools) && options.tools.length > 0;

            // Normalize model
            if (options.model || input.model?.id) {
                options.model = normalizeModelId(options.model || input.model?.id);
            }

            // Normalize tools
            options.tools = normalizeToolsForClaude(options.tools);

            // Normalize messages
            if (Array.isArray(options.messages)) {
                options.messages = normalizeMessagesForClaude(options.messages);
            }

            // Remove unsupported fields
            delete options.temperature;
            delete options.tool_choice;

            // Headers
            const headers =
                options.headers instanceof Headers
                    ? options.headers
                    : new Headers(options.headers ?? {});

            const betaHeaders = getBetaHeadersForPath("/v1/messages", hasTools);
            headers.set("anthropic-beta", betaHeaders.join(","));
            applyStainlessHeaders(headers, !!options.stream);

            options.headers = headers;

            // Metadata
            const userId = await resolveMetadataUserId();
            if (userId) {
                options.metadata = { ...(options.metadata ?? {}), user_id: userId };
            }
        },
    };
}
