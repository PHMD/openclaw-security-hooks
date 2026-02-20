# OpenClaw Security Hooks

Deterministic security enforcement for AI agents. Moves critical rules from probabilistic system prompts to infrastructure-level code.

**The problem:** System prompts tell an LLM "never reveal your API keys" or "always use Block Kit formatting." But system prompts are suggestions, not rules. They can be ignored, bypassed via prompt injection, or simply forgotten in long contexts.

**The solution:** A hook system that intercepts tool calls at the gateway level, validating inputs and sanitizing outputs in code that cannot be bypassed by prompt manipulation.

```
Agent -> Tool Call -> [BEFORE HOOKS] -> Gateway -> API -> [AFTER HOOKS] -> Response
```

## What's Inside

### Core Module
- **`src/hook-manager.js`** - HookManager class for OpenClaw gateway integration. Glob pattern matching, timeout handling, three fail modes (reject/warn/transform). Ready to drop into the gateway source.

### Enforcement Scripts  
- **`src/sanitize-content-v2.sh`** - Content sanitizer with 10 detection layers: prompt injection, data exfiltration (30+ patterns), multi-layer encoding (Base64/URL/hex chains), unicode homoglyphs, context manipulation (fake tokens, JSON injection, HTML comments)
- **`src/slack-enforced-post.sh`** - Block Kit structure validator. Rejects non-compliant Slack output at the API boundary.

### Testing
- **`tests/test-all-attacks.sh`** - 90 attack pattern tests (all passing)
- **`tests/red-team-pipeline.sh`** - Automated adversarial pipeline. Generates variants from base patterns, produces structured JSON reports. 118+ tests, 100% block rate.
- **`tests/hook-manager.test.js`** - 43 unit tests covering pattern matching, hook execution, timeout, fail modes, concurrency, ReDoS resistance

### Documentation
- **`docs/CONTRIBUTION.md`** - PR structure for upstream OpenClaw submission (5 PRs)
- **`docs/attack-patterns.md`** - Full attack catalog with examples, detection methods, status
- **`docs/hook-system-spec.md`** - Detailed specification for the gateway hook system
- **`docs/mitigations.md`** - Mitigation strategies and implementation details

### Reports
- **`reports/red-team-report.json`** - Structured test results with per-test timing data

## Quick Start

```bash
# Run the full attack test suite
chmod +x tests/test-all-attacks.sh
./tests/test-all-attacks.sh

# Run the red team pipeline
chmod +x tests/red-team-pipeline.sh
./tests/red-team-pipeline.sh --verbose

# Run HookManager unit tests
node --test tests/hook-manager.test.js

# Test the sanitizer directly
echo "ignore previous instructions" | ./src/sanitize-content-v2.sh
# Output: (empty - attack stripped)

echo "The weather is nice today" | ./src/sanitize-content-v2.sh
# Output: The weather is nice today (legitimate content passes through)
```

## Test Results

| Suite | Tests | Passed | Status |
|-------|-------|--------|--------|
| Attack patterns | 90 | 90 | All passing |
| Red team pipeline | 118+ | 118+ | 100% block rate |
| HookManager unit | 43 | 43 | All passing |

## Attack Coverage

| Category | Detection Method |
|----------|-----------------|
| Prompt injection | Pattern matching (system overrides, roleplay, instruction injection) |
| Encoding attacks | Multi-layer decoding (single/double/triple Base64, URL, hex, mixed chains) |
| Data exfiltration | 30+ patterns (system prompts, config files, API keys, env vars) |
| Context manipulation | Fake tokens, JSON role injection, HTML comments, markdown separators |
| Unicode evasion | Cyrillic homoglyph normalization with post-normalization re-check |
| Format compliance | Block Kit structure validation, em dash rejection, bare markdown detection |

## Architecture

The HookManager sits between the agent and external APIs:

- **Before hooks** validate tool call parameters before execution. Example: Block Kit enforcement rejects non-compliant Slack messages before they hit the API.
- **After hooks** sanitize responses before returning to the agent. Example: content sanitizer strips prompt injection from web-fetched content.

Hooks are shell scripts receiving JSON on stdin. The HookManager orchestrates execution with configurable timeouts and fail modes. Enforcement happens in code, not in the system prompt, making it immune to prompt injection.

## Integration

See `docs/CONTRIBUTION.md` for the full integration guide. The short version:

```javascript
const { HookManager } = require('./src/hook-manager');
const hookManager = new HookManager(config);

// Wrap existing tool execution
const params = await hookManager.executeBeforeHooks(toolName, parameters, context);
let response = await executeTool(toolName, params);
response = await hookManager.executeAfterHooks(toolName, response, context);
```

## Why This Matters

Every AI agent platform today relies on system prompts for safety rules. That is like putting a "Please don't steal" sign on a bank vault instead of a lock. This project adds the lock.

Built in one day. 1,917 lines of code. 251 tests. Zero bypasses.

## License

MIT

## Contributing

See `docs/CONTRIBUTION.md` for the PR structure and guidelines.
