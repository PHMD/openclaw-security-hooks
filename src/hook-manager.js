/**
 * HookManager - Deterministic enforcement hooks for OpenClaw gateway
 * 
 * Provides infrastructure-level validation of tool calls via before/after hooks.
 * Hooks are shell scripts that receive JSON on stdin and return results via
 * exit codes and stdout.
 * 
 * @module hook-manager
 */

const { spawn } = require('child_process');
const path = require('path');

/**
 * Matches a hook pattern against a tool call key.
 * Supports glob patterns: before:* matches all before hooks,
 * after:message.* matches after:message.send, after:message.read, etc.
 *
 * @param {string} pattern - Hook pattern (e.g., "before:*", "after:message.*")
 * @param {string} key - Tool call key (e.g., "before:message.send")
 * @returns {boolean}
 */
function matchPattern(pattern, key) {
    if (pattern === key) return true;
    if (!pattern.includes('*')) return false;

    // Escape special regex characters except * and .
    // First escape backslashes, then other special chars, but preserve * and .
    const escaped = pattern
        .replace(/[+?^${}()|[\]\\]/g, '\\$&')  // Escape special regex chars
        .replace(/\./g, '\\.')                   // Escape dots (literal in our patterns)
        .replace(/\*/g, '.*');                   // Convert * to regex .*

    // Use non-backtracking strategy by limiting .* greediness context
    const regex = new RegExp('^' + escaped + '$');
    return regex.test(key);
}

/**
 * @typedef {Object} HookConfig
 * @property {string} name - Identifier for the hook
 * @property {string} script - Path to executable hook script
 * @property {'reject'|'warn'|'transform'} failMode - How to handle hook failures
 * @property {number} [timeout=5000] - Maximum execution time in ms
 * @property {boolean} [transform=false] - Whether hook output replaces original data
 */

/**
 * @typedef {Object} HookResult
 * @property {boolean} success - Whether hook executed successfully
 * @property {boolean} [reject] - Whether hook rejected the call
 * @property {string} [error] - Error message if rejected/failed
 * @property {string} [output] - Hook stdout (for transform mode)
 */

class HookManager {
    /**
     * @param {Object} config - Gateway configuration object
     * @param {Object.<string, HookConfig[]>} config.hooks - Hook definitions keyed by pattern
     */
    constructor(config) {
        this.hooks = config.hooks || {};
        this._validateConfig();
    }

    /**
     * Validate hook configuration on initialization
     * @private
     */
    _validateConfig() {
        for (const [pattern, hooks] of Object.entries(this.hooks)) {
            if (!Array.isArray(hooks)) {
                throw new Error(`Hook configuration for pattern '${pattern}' must be an array`);
            }

            for (const hook of hooks) {
                if (!hook.name || typeof hook.name !== 'string') {
                    throw new Error(`Hook must have a valid 'name' property`);
                }
                if (!hook.script || typeof hook.script !== 'string') {
                    throw new Error(`Hook '${hook.name}' must have a valid 'script' property`);
                }
                if (!['reject', 'warn', 'transform'].includes(hook.failMode)) {
                    throw new Error(`Hook '${hook.name}' has invalid failMode: ${hook.failMode}`);
                }
                if (hook.timeout !== undefined && (typeof hook.timeout !== 'number' || hook.timeout <= 0)) {
                    throw new Error(`Hook '${hook.name}' has invalid timeout: ${hook.timeout}`);
                }
                // Basic path validation - prevent obvious path traversal
                if (hook.script.includes('..') || hook.script.includes('\0')) {
                    throw new Error(`Hook '${hook.name}' has suspicious script path: ${hook.script}`);
                }
            }
        }
    }

    /**
     * Find all hooks matching a given key, including glob patterns.
     * 
     * @param {string} key - The hook key to match (e.g., "before:message.send")
     * @returns {HookConfig[]} Matching hook configurations
     */
    findHooks(key) {
        const matched = [];
        for (const [pattern, hooks] of Object.entries(this.hooks)) {
            if (matchPattern(pattern, key)) {
                matched.push(...hooks);
            }
        }
        return matched;
    }

    /**
     * Execute all before hooks for a tool call.
     * Hooks run in order. A rejecting hook stops execution.
     * Transform hooks modify parameters for subsequent hooks and the tool call.
     * 
     * @param {string} toolName - Tool being called (e.g., "message.send")
     * @param {Object} parameters - Tool call parameters
     * @param {Object} context - Execution context (user, session, etc.)
     * @returns {Promise<Object>} Potentially transformed parameters
     * @throws {Error} If a hook with failMode 'reject' fails
     */
    async executeBeforeHooks(toolName, parameters, context) {
        const hookKey = `before:${toolName}`;
        const hooks = this.findHooks(hookKey);

        for (const hook of hooks) {
            const result = await this.executeHook(hook, {
                tool: toolName,
                phase: 'before',
                parameters,
                context
            });

            if (result.reject) {
                throw new Error(`Hook ${hook.name} rejected: ${result.error}`);
            }

            if (hook.transform && result.output) {
                try {
                    parameters = JSON.parse(result.output);
                } catch (e) {
                    console.warn(`Hook ${hook.name}: transform output not valid JSON`);
                }
            }
        }

        return parameters;
    }

    /**
     * Execute all after hooks for a tool response.
     * Transform hooks modify the response before returning to the agent.
     * 
     * @param {string} toolName - Tool that was called
     * @param {*} response - Tool response data
     * @param {Object} context - Execution context
     * @returns {Promise<*>} Potentially transformed response
     */
    async executeAfterHooks(toolName, response, context) {
        const hookKey = `after:${toolName}`;
        const hooks = this.findHooks(hookKey);

        for (const hook of hooks) {
            const result = await this.executeHook(hook, {
                tool: toolName,
                phase: 'after',
                response,
                context
            });

            if (hook.transform && result.output) {
                try {
                    response = JSON.parse(result.output);
                } catch (e) {
                    console.warn(`Hook ${hook.name}: transform output not valid JSON`);
                }
            }
        }

        return response;
    }

    /**
     * Execute a single hook script.
     * Sends data as JSON on stdin, reads stdout/stderr, respects timeout.
     *
     * @param {HookConfig} hook - Hook configuration
     * @param {Object} data - Data to send to hook script
     * @returns {Promise<HookResult>}
     */
    executeHook(hook, data) {
        return new Promise((resolve) => {
            const timeout = hook.timeout || 5000;
            const maxOutputSize = 10 * 1024 * 1024; // 10MB limit
            let stdout = '';
            let stderr = '';
            let settled = false;
            let outputTruncated = false;

            const finish = (result) => {
                if (settled) return;
                settled = true;
                if (timer) clearTimeout(timer);
                if (proc && !proc.killed) {
                    proc.kill('SIGTERM');
                }
                resolve(result);
            };

            let proc;
            try {
                proc = spawn(hook.script, [], {
                    stdio: ['pipe', 'pipe', 'pipe'],
                    env: process.env,
                    shell: false  // Prevent shell injection
                });
            } catch (err) {
                if (hook.failMode === 'reject') {
                    return resolve({ reject: true, error: `Hook ${hook.name} spawn error: ${err.message}` });
                } else {
                    console.warn(`Hook ${hook.name} spawn error: ${err.message}`);
                    return resolve({ success: true });
                }
            }

            // Write input data to stdin with proper error handling
            const input = JSON.stringify(data);
            let writeError = false;

            proc.stdin.on('error', (err) => {
                // EPIPE is expected if process exits before reading all input
                if (err.code !== 'EPIPE') {
                    writeError = true;
                }
            });

            try {
                proc.stdin.write(input, (err) => {
                    if (err && err.code !== 'EPIPE') {
                        writeError = true;
                    }
                });
                proc.stdin.end();
            } catch (e) {
                // Synchronous EPIPE - process already exited, which is fine
                if (e.code !== 'EPIPE') {
                    writeError = true;
                }
            }

            // Accumulate output with size limits to prevent memory DoS
            proc.stdout.on('data', (d) => {
                if (stdout.length + d.length > maxOutputSize) {
                    outputTruncated = true;
                    stdout += d.toString().slice(0, maxOutputSize - stdout.length);
                    proc.stdout.pause();
                } else {
                    stdout += d;
                }
            });

            proc.stderr.on('data', (d) => {
                if (stderr.length + d.length > maxOutputSize) {
                    stderr += d.toString().slice(0, maxOutputSize - stderr.length);
                    proc.stderr.pause();
                } else {
                    stderr += d;
                }
            });

            const timer = setTimeout(() => {
                proc.kill('SIGKILL');
                if (hook.failMode === 'reject') {
                    finish({ reject: true, error: `Hook ${hook.name} timed out after ${timeout}ms` });
                } else {
                    console.warn(`Hook ${hook.name} timed out after ${timeout}ms`);
                    finish({ success: true });
                }
            }, timeout);

            proc.on('error', (err) => {
                if (hook.failMode === 'reject') {
                    finish({ reject: true, error: `Hook ${hook.name} error: ${err.message}` });
                } else {
                    console.warn(`Hook ${hook.name} error: ${err.message}`);
                    finish({ success: true });
                }
            });

            proc.on('close', (code, signal) => {
                if (outputTruncated) {
                    console.warn(`Hook ${hook.name} output truncated (exceeded ${maxOutputSize} bytes)`);
                }

                if (code === 0) {
                    finish({ success: true, output: stdout.trim() });
                } else {
                    const error = stderr.trim() || `Hook exited with code ${code}${signal ? ` (signal ${signal})` : ''}`;
                    if (hook.failMode === 'reject') {
                        finish({ reject: true, error });
                    } else {
                        console.warn(`Hook ${hook.name} failed: ${error}`);
                        finish({ success: true, output: stdout.trim() });
                    }
                }
            });
        });
    }
}

module.exports = { HookManager, matchPattern };
