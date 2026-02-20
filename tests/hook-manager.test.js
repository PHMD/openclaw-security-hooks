const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { HookManager, matchPattern } = require('./hook-manager');

// Create temp hook scripts for testing
const TEMP_DIR = '/tmp/hook-test-scripts';

before(() => {
    fs.mkdirSync(TEMP_DIR, { recursive: true });

    // Hook that succeeds
    fs.writeFileSync(`${TEMP_DIR}/pass.sh`, '#!/bin/bash\ncat\n', { mode: 0o755 });

    // Hook that fails (reject)
    fs.writeFileSync(`${TEMP_DIR}/reject.sh`, '#!/bin/bash\necho "Blocked by policy" >&2\nexit 1\n', { mode: 0o755 });

    // Hook that transforms (uppercases the tool name in params)
    fs.writeFileSync(`${TEMP_DIR}/transform.sh`, `#!/bin/bash
read input
echo "$input" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if 'parameters' in d:
    d['parameters']['transformed'] = True
print(json.dumps(d['parameters']))
"`, { mode: 0o755 });

    // Hook that times out
    fs.writeFileSync(`${TEMP_DIR}/slow.sh`, '#!/bin/bash\nsleep 30\n', { mode: 0o755 });

    // Hook that outputs custom JSON
    fs.writeFileSync(`${TEMP_DIR}/custom-output.sh`, '#!/bin/bash\necho \'{"sanitized": true, "content": "clean"}\'\n', { mode: 0o755 });
});

after(() => {
    fs.rmSync(TEMP_DIR, { recursive: true, force: true });
});

describe('matchPattern', () => {
    it('matches exact keys', () => {
        assert.ok(matchPattern('before:message.send', 'before:message.send'));
    });

    it('rejects non-matching keys', () => {
        assert.ok(!matchPattern('before:message.send', 'before:web_fetch'));
    });

    it('matches wildcard patterns', () => {
        assert.ok(matchPattern('before:*', 'before:message.send'));
        assert.ok(matchPattern('before:*', 'before:web_fetch'));
    });

    it('matches partial wildcards', () => {
        assert.ok(matchPattern('after:message.*', 'after:message.send'));
        assert.ok(matchPattern('after:message.*', 'after:message.read'));
        assert.ok(!matchPattern('after:message.*', 'after:web_fetch'));
    });
});

describe('HookManager.findHooks', () => {
    it('finds exact match hooks', () => {
        const hm = new HookManager({
            hooks: {
                'before:message.send': [{ name: 'test', script: '/bin/true', failMode: 'warn' }]
            }
        });
        const found = hm.findHooks('before:message.send');
        assert.strictEqual(found.length, 1);
        assert.strictEqual(found[0].name, 'test');
    });

    it('finds glob match hooks', () => {
        const hm = new HookManager({
            hooks: {
                'before:*': [{ name: 'global', script: '/bin/true', failMode: 'warn' }],
                'before:message.send': [{ name: 'specific', script: '/bin/true', failMode: 'warn' }]
            }
        });
        const found = hm.findHooks('before:message.send');
        assert.strictEqual(found.length, 2);
    });

    it('returns empty for no matches', () => {
        const hm = new HookManager({ hooks: {} });
        assert.strictEqual(hm.findHooks('before:anything').length, 0);
    });
});

describe('HookManager.executeHook', () => {
    it('executes passing hook', async () => {
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'pass', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 },
            { tool: 'test', parameters: { x: 1 } }
        );
        assert.ok(result.success);
    });

    it('handles rejecting hook with reject failMode', async () => {
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'reject', script: `${TEMP_DIR}/reject.sh`, failMode: 'reject', timeout: 5000 },
            { tool: 'test' }
        );
        assert.ok(result.reject);
        assert.ok(result.error.includes('Blocked by policy'));
    });

    it('handles failing hook with warn failMode', async () => {
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'reject', script: `${TEMP_DIR}/reject.sh`, failMode: 'warn', timeout: 5000 },
            { tool: 'test' }
        );
        assert.ok(result.success);
    });

    it('handles timeout', async () => {
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'slow', script: `${TEMP_DIR}/slow.sh`, failMode: 'reject', timeout: 200 },
            { tool: 'test' }
        );
        assert.ok(result.reject);
        assert.ok(result.error.includes('timed out'));
    });

    it('returns output for transform hooks', async () => {
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'custom', script: `${TEMP_DIR}/custom-output.sh`, failMode: 'warn', timeout: 5000, transform: true },
            { tool: 'test' }
        );
        assert.ok(result.success);
        const parsed = JSON.parse(result.output);
        assert.strictEqual(parsed.sanitized, true);
    });
});

describe('HookManager.executeBeforeHooks', () => {
    it('passes parameters through on success', async () => {
        const hm = new HookManager({
            hooks: {
                'before:test.call': [{ name: 'pass', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 }]
            }
        });
        const params = await hm.executeBeforeHooks('test.call', { x: 1 }, {});
        assert.deepStrictEqual(params, { x: 1 });
    });

    it('throws on reject', async () => {
        const hm = new HookManager({
            hooks: {
                'before:test.call': [{ name: 'blocker', script: `${TEMP_DIR}/reject.sh`, failMode: 'reject', timeout: 5000 }]
            }
        });
        await assert.rejects(
            () => hm.executeBeforeHooks('test.call', { x: 1 }, {}),
            /Hook blocker rejected/
        );
    });

    it('transforms parameters', async () => {
        const hm = new HookManager({
            hooks: {
                'before:test.call': [{
                    name: 'transformer',
                    script: `${TEMP_DIR}/custom-output.sh`,
                    failMode: 'warn',
                    timeout: 5000,
                    transform: true
                }]
            }
        });
        const params = await hm.executeBeforeHooks('test.call', { x: 1 }, {});
        assert.strictEqual(params.sanitized, true);
    });
});

describe('HookManager.executeAfterHooks', () => {
    it('transforms response', async () => {
        const hm = new HookManager({
            hooks: {
                'after:web_fetch': [{
                    name: 'sanitizer',
                    script: `${TEMP_DIR}/custom-output.sh`,
                    failMode: 'warn',
                    timeout: 5000,
                    transform: true
                }]
            }
        });
        const response = await hm.executeAfterHooks('web_fetch', { content: 'raw' }, {});
        assert.strictEqual(response.sanitized, true);
    });

    it('skips non-matching hooks', async () => {
        const hm = new HookManager({
            hooks: {
                'after:other': [{
                    name: 'other',
                    script: `${TEMP_DIR}/custom-output.sh`,
                    failMode: 'warn',
                    timeout: 5000,
                    transform: true
                }]
            }
        });
        const response = await hm.executeAfterHooks('web_fetch', { content: 'raw' }, {});
        assert.deepStrictEqual(response, { content: 'raw' });
    });
});

describe('Edge Cases and Security Tests', () => {
    it('handles malformed JSON in transform gracefully', async () => {
        fs.writeFileSync(`${TEMP_DIR}/bad-json.sh`, '#!/bin/bash\necho "not json at all"\n', { mode: 0o755 });
        const hm = new HookManager({
            hooks: {
                'before:test': [{
                    name: 'bad-json',
                    script: `${TEMP_DIR}/bad-json.sh`,
                    failMode: 'warn',
                    timeout: 5000,
                    transform: true
                }]
            }
        });
        const params = await hm.executeBeforeHooks('test', { original: true }, {});
        // Should keep original params if transform fails
        assert.strictEqual(params.original, true);
    });

    it('handles very large output', async () => {
        fs.writeFileSync(`${TEMP_DIR}/large-output.sh`, '#!/bin/bash\nfor i in {1..10000}; do echo "line $i"; done\n', { mode: 0o755 });
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'large', script: `${TEMP_DIR}/large-output.sh`, failMode: 'warn', timeout: 5000 },
            { tool: 'test' }
        );
        assert.ok(result.success);
        assert.ok(result.output.length > 50000);
    });

    it('handles hook script that does not exist', async () => {
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'missing', script: `${TEMP_DIR}/does-not-exist.sh`, failMode: 'reject', timeout: 5000 },
            { tool: 'test' }
        );
        assert.ok(result.reject);
        assert.ok(result.error.includes('error'));
    });

    it('handles hook script that is not executable', async () => {
        fs.writeFileSync(`${TEMP_DIR}/not-exec.sh`, '#!/bin/bash\necho "test"\n', { mode: 0o644 });
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'not-exec', script: `${TEMP_DIR}/not-exec.sh`, failMode: 'reject', timeout: 5000 },
            { tool: 'test' }
        );
        assert.ok(result.reject);
    });

    it('handles empty config gracefully', async () => {
        const hm = new HookManager({});
        const params = await hm.executeBeforeHooks('test', { x: 1 }, {});
        assert.deepStrictEqual(params, { x: 1 });
    });

    it('handles hook that exits immediately', async () => {
        fs.writeFileSync(`${TEMP_DIR}/fast-exit.sh`, '#!/bin/bash\nexit 0\n', { mode: 0o755 });
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'fast', script: `${TEMP_DIR}/fast-exit.sh`, failMode: 'warn', timeout: 5000 },
            { tool: 'test' }
        );
        assert.ok(result.success);
    });

    it('handles hook that closes stdin and continues processing', async () => {
        fs.writeFileSync(`${TEMP_DIR}/ignore-stdin.sh`, '#!/bin/bash\nexec 0<&-\necho "processed"\nexit 0\n', { mode: 0o755 });
        const hm = new HookManager({ hooks: {} });
        const result = await hm.executeHook(
            { name: 'ignore-stdin', script: `${TEMP_DIR}/ignore-stdin.sh`, failMode: 'warn', timeout: 5000 },
            { tool: 'test', data: 'x'.repeat(100000) }
        );
        assert.ok(result.success);
        assert.strictEqual(result.output, 'processed');
    });

    it('executes multiple hooks in sequence', async () => {
        const hm = new HookManager({
            hooks: {
                'before:test': [
                    { name: 'first', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 },
                    { name: 'second', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 },
                    { name: 'third', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 }
                ]
            }
        });
        const params = await hm.executeBeforeHooks('test', { x: 1 }, {});
        assert.deepStrictEqual(params, { x: 1 });
    });

    it('stops execution on first reject in chain', async () => {
        let executionOrder = [];
        const hm = new HookManager({
            hooks: {
                'before:test': [
                    { name: 'first', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 },
                    { name: 'second', script: `${TEMP_DIR}/reject.sh`, failMode: 'reject', timeout: 5000 },
                    { name: 'third', script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 }
                ]
            }
        });
        await assert.rejects(
            () => hm.executeBeforeHooks('test', { x: 1 }, {}),
            /Hook second rejected/
        );
    });
});

describe('Glob Pattern Edge Cases', () => {
    it('handles special regex characters in pattern', () => {
        assert.ok(matchPattern('before:test.foo', 'before:test.foo'));
        assert.ok(!matchPattern('before:test+foo', 'before:testfoo'));
    });

    it('handles multiple wildcards', () => {
        assert.ok(matchPattern('*:*', 'before:test'));
        assert.ok(matchPattern('*:*', 'after:test'));
        assert.ok(matchPattern('before:*.*', 'before:message.send'));
    });

    it('handles edge case patterns', () => {
        assert.ok(matchPattern('*', 'anything'));
        assert.ok(matchPattern('before:*', 'before:'));
        assert.ok(!matchPattern('before:test.*', 'before:test'));
    });

    it('handles empty and unusual patterns', () => {
        assert.ok(!matchPattern('', 'before:test'));
        assert.ok(matchPattern('', ''));
    });

    it('handles patterns with multiple consecutive dots', () => {
        assert.ok(matchPattern('before:a.b.c.d', 'before:a.b.c.d'));
        assert.ok(matchPattern('before:a.*.d', 'before:a.b.c.d'));
    });

    it('handles patterns with escaped characters', () => {
        // Pattern should treat dots literally
        assert.ok(!matchPattern('before:testXfoo', 'before:test.foo'));
    });

    it('handles very long patterns', () => {
        const longPattern = 'before:' + 'a.'.repeat(100) + '*';
        const longKey = 'before:' + 'a.'.repeat(100) + 'test';
        assert.ok(matchPattern(longPattern, longKey));
    });

    it('handles potentially catastrophic backtracking patterns', () => {
        // These patterns should not hang
        const start = Date.now();
        matchPattern('before:*.*.*.*.*.*.*', 'before:a.b.c.d.e.f.g.h.i.j.k');
        const elapsed = Date.now() - start;
        assert.ok(elapsed < 100, 'Pattern matching should be fast');
    });
});

describe('Concurrent Execution', () => {
    it('handles concurrent hook executions', async () => {
        const hm = new HookManager({ hooks: {} });
        const promises = Array.from({ length: 10 }, (_, i) =>
            hm.executeHook(
                { name: `concurrent-${i}`, script: `${TEMP_DIR}/pass.sh`, failMode: 'warn', timeout: 5000 },
                { tool: 'test', index: i }
            )
        );
        const results = await Promise.all(promises);
        assert.strictEqual(results.length, 10);
        assert.ok(results.every(r => r.success));
    });
});

describe('Configuration Validation', () => {
    it('rejects invalid hook configuration - not an array', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': { name: 'test', script: '/bin/true', failMode: 'warn' }
                }
            });
        }, /must be an array/);
    });

    it('rejects hook without name', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ script: '/bin/true', failMode: 'warn' }]
                }
            });
        }, /must have a valid 'name'/);
    });

    it('rejects hook without script', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ name: 'test', failMode: 'warn' }]
                }
            });
        }, /must have a valid 'script'/);
    });

    it('rejects hook with invalid failMode', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ name: 'test', script: '/bin/true', failMode: 'invalid' }]
                }
            });
        }, /invalid failMode/);
    });

    it('rejects hook with invalid timeout', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ name: 'test', script: '/bin/true', failMode: 'warn', timeout: -100 }]
                }
            });
        }, /invalid timeout/);
    });

    it('rejects hook with path traversal in script', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ name: 'test', script: '../../../etc/passwd', failMode: 'warn' }]
                }
            });
        }, /suspicious script path/);
    });

    it('rejects hook with null byte in script path', () => {
        assert.throws(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ name: 'test', script: '/bin/true\0/etc/passwd', failMode: 'warn' }]
                }
            });
        }, /suspicious script path/);
    });

    it('accepts valid configuration', () => {
        assert.doesNotThrow(() => {
            new HookManager({
                hooks: {
                    'before:test': [{ name: 'test', script: '/bin/true', failMode: 'warn', timeout: 1000 }]
                }
            });
        });
    });
});
