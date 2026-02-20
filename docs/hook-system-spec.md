# OpenClaw Gateway Hook System Specification

## Overview

This document specifies a deterministic enforcement architecture for OpenClaw that moves security and formatting enforcement from probabilistic system prompts to infrastructure-level hooks. This addresses the core problem that LLMs can bypass safety/formatting rules when those rules exist only in system prompts.

## Current Problem

**Probabilistic Enforcement (Current State):**
- Block Kit formatting enforced via system prompt instructions
- Safety rules defined in natural language prompts
- LLMs can ignore, misinterpret, or be tricked into bypassing these rules
- Inconsistent enforcement across different model versions/contexts
- No guarantee of rule adherence

**Deterministic Enforcement (Target State):**
- Infrastructure-level validation at the gateway
- Rules enforced in code before/after tool calls
- Impossible to bypass via prompt manipulation
- Consistent enforcement regardless of model behavior
- Auditable and testable

## Architecture

### Hook Integration Points

The gateway currently handles tool calls through this flow:
```
User Input → Agent (LLM) → Tool Call → Gateway → External API → Response → Agent → User
```

We propose adding hook points:
```
User Input → Agent (LLM) → Tool Call → [BEFORE HOOKS] → Gateway → External API → [AFTER HOOKS] → Response → Agent → User
```

### Hook Types

**Before Hooks** (`before:toolname`):
- Validate/transform tool call parameters before execution
- Reject invalid calls with error messages
- Transform parameters to ensure compliance
- Examples: Block Kit validation, content sanitization

**After Hooks** (`after:toolname`):
- Process tool responses before returning to agent
- Sanitize returned content
- Add metadata/logging
- Examples: Content sanitization, security scanning

## Configuration Format

Add to `openclaw.json`:

```json
{
  "hooks": {
    "before:message.send": [
      {
        "name": "block-kit-enforcer",
        "script": "/root/.openclaw/workspace/scripts/slack-enforced-post.sh",
        "failMode": "reject",
        "timeout": 5000
      }
    ],
    "after:web_fetch": [
      {
        "name": "content-sanitizer",
        "script": "/root/.openclaw/workspace/scripts/sanitize-content.sh",
        "failMode": "warn",
        "timeout": 3000,
        "transform": true
      }
    ],
    "before:*": [
      {
        "name": "global-audit-logger",
        "script": "/root/.openclaw/workspace/scripts/audit-logger.sh",
        "failMode": "warn",
        "timeout": 1000
      }
    ]
  }
}
```

### Hook Configuration Properties

- **name**: Identifier for the hook (for logging/debugging)
- **script**: Path to executable script that implements the hook
- **failMode**: How to handle hook failures
  - `reject`: Block the tool call with error
  - `warn`: Log warning but continue
  - `transform`: Use hook output as transformed input/output
- **timeout**: Maximum execution time in milliseconds
- **transform**: Boolean - whether hook output replaces original data

## Hook Script Interface

### Before Hook Scripts

**Input**: JSON via stdin containing tool call parameters
```json
{
  "tool": "message",
  "action": "send", 
  "parameters": {
    "channel": "C123456789",
    "text": "Hello world"
  },
  "context": {
    "user": "patrick",
    "session": "abc123"
  }
}
```

**Output**: 
- Exit code 0 = success, continue
- Exit code 1 = reject with error message on stderr
- If `transform: true`, stdout contains transformed parameters JSON

### After Hook Scripts

**Input**: JSON via stdin containing tool response
```json
{
  "tool": "web_fetch",
  "response": {
    "content": "Fetched web content here...",
    "url": "https://example.com"
  },
  "context": {
    "user": "patrick", 
    "session": "abc123"
  }
}
```

**Output**:
- Exit code 0 = success
- If `transform: true`, stdout contains transformed response JSON

## Implementation in Gateway (Node.js)

```javascript
// hooks.js
class HookManager {
  constructor(config) {
    this.hooks = config.hooks || {};
  }

  async executeBeforeHooks(toolName, parameters, context) {
    const hookKey = `before:${toolName}`;
    const globalHooks = this.hooks['before:*'] || [];
    const specificHooks = this.hooks[hookKey] || [];
    
    for (const hook of [...globalHooks, ...specificHooks]) {
      const result = await this.executeHook(hook, {
        tool: toolName,
        parameters,
        context
      });
      
      if (result.reject) {
        throw new Error(`Hook ${hook.name} rejected: ${result.error}`);
      }
      
      if (hook.transform && result.output) {
        parameters = JSON.parse(result.output);
      }
    }
    
    return parameters;
  }

  async executeAfterHooks(toolName, response, context) {
    const hookKey = `after:${toolName}`;
    const hooks = this.hooks[hookKey] || [];
    
    for (const hook of hooks) {
      const result = await this.executeHook(hook, {
        tool: toolName,
        response,
        context
      });
      
      if (hook.transform && result.output) {
        response = JSON.parse(result.output);
      }
    }
    
    return response;
  }

  async executeHook(hook, data) {
    const { spawn } = require('child_process');
    
    return new Promise((resolve, reject) => {
      const process = spawn(hook.script, []);
      let stdout = '';
      let stderr = '';
      
      process.stdin.write(JSON.stringify(data));
      process.stdin.end();
      
      process.stdout.on('data', (data) => {
        stdout += data;
      });
      
      process.stderr.on('data', (data) => {
        stderr += data;
      });
      
      const timeout = setTimeout(() => {
        process.kill();
        reject(new Error(`Hook ${hook.name} timed out`));
      }, hook.timeout || 5000);
      
      process.on('close', (code) => {
        clearTimeout(timeout);
        
        if (code === 0) {
          resolve({ success: true, output: stdout });
        } else {
          const error = stderr || `Hook exited with code ${code}`;
          
          if (hook.failMode === 'reject') {
            resolve({ reject: true, error });
          } else {
            console.warn(`Hook ${hook.name} failed: ${error}`);
            resolve({ success: true });
          }
        }
      });
    });
  }
}

// Integration into existing tool handlers
async function handleToolCall(toolName, parameters, context) {
  const hookManager = new HookManager(config);
  
  // Execute before hooks
  const validatedParams = await hookManager.executeBeforeHooks(
    toolName, parameters, context
  );
  
  // Execute the actual tool
  let response = await executeTool(toolName, validatedParams);
  
  // Execute after hooks
  response = await hookManager.executeAfterHooks(
    toolName, response, context
  );
  
  return response;
}
```

## Example Implementations

### Block Kit Enforcement Hook

Our existing `/root/.openclaw/workspace/scripts/slack-enforced-post.sh` already implements the before hook pattern for message.send:

- Validates Block Kit structure
- Rejects non-compliant payloads
- Logs all attempts
- Returns appropriate exit codes

### Content Sanitization Hook

Our existing `/root/.openclaw/workspace/scripts/sanitize-content.sh` implements the after hook pattern for web_fetch:

- Strips prompt injection patterns
- Neutralizes encoded attacks
- Logs sanitization actions
- Transforms content while preserving legitimate text

## Benefits Over System Prompt Enforcement

### Deterministic vs Probabilistic

| System Prompts (Probabilistic) | Hooks (Deterministic) |
|--------------------------------|------------------------|
| Can be ignored by model | Cannot be bypassed |
| Inconsistent across contexts | Consistent enforcement |
| Natural language ambiguity | Code-based precision |
| Model-dependent behavior | Model-agnostic |
| Hard to test comprehensively | Easy to unit test |

### Security Guarantees

- **Immutable**: Hook logic cannot be modified by model output
- **Auditable**: All enforcement actions logged with timestamps
- **Testable**: Scripts can be tested in isolation
- **Fail-safe**: Configurable failure modes prevent bypasses
- **Transparent**: Clear separation of enforcement vs AI behavior

## Integration Challenges

### Performance Impact
- Each hook adds latency to tool calls
- Timeout mechanisms prevent hanging
- Parallel hook execution where possible

### Error Handling
- Clear error messages for rejected calls
- Graceful degradation options
- Debug logging for troubleshooting

### Development Workflow
- Hook scripts must be executable and tested
- Version control for hook configurations
- Rollback mechanisms for problematic hooks

## Contribution Plan for OpenClaw

### Phase 1: Core Hook Infrastructure
- Implement `HookManager` class in gateway
- Add hook configuration parsing
- Basic before/after hook execution
- Unit tests for hook system

### Phase 2: Tool Integration
- Integrate hooks into existing tool handlers
- Add hook context passing
- Error handling and timeout management
- Performance optimization

### Phase 3: Advanced Features
- Parallel hook execution
- Hook dependency management
- Dynamic hook loading/reloading
- Web interface for hook management

### Phase 4: Security Enhancements
- Hook signature verification
- Sandboxed hook execution
- Resource limits and monitoring
- Security audit logging

## Deliverables for PR

1. **Core Implementation**:
   - `lib/hooks.js` - Hook manager class
   - Integration into existing tool handlers
   - Configuration schema validation

2. **Documentation**:
   - Hook development guide
   - Security considerations
   - Performance best practices
   - Migration guide from prompt-based rules

3. **Examples**:
   - Block Kit enforcement hook
   - Content sanitization hook
   - Audit logging hook
   - Rate limiting hook

4. **Tests**:
   - Hook manager unit tests
   - Integration tests with sample hooks
   - Performance benchmarks
   - Security validation tests

This hook system transforms OpenClaw from a model-dependent platform to one with infrastructure-level guarantees, making it suitable for production environments where deterministic behavior is critical.