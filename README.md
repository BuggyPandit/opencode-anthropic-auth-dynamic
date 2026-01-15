# opencode-anthropic-auth-dynamic

[OpenCode](https://github.com/opencode-ai/opencode) plugin for Anthropic OAuth authentication. Use your Claude Pro/Max subscription with OpenCode.

## Install

### Via npm

```bash
npm install opencode-anthropic-auth-dynamic
```

Add to `~/.config/opencode/opencode.json`:

```json
{
    "plugin": ["opencode-anthropic-auth-dynamic"]
}
```

### Local Development

```bash
git clone https://github.com/BuggyPandit/opencode-anthropic-auth-dynamic.git
cd opencode-anthropic-auth-dynamic
npm install
```

Add to `~/.config/opencode/opencode.json`:

```json
{
    "plugin": ["file:///path/to/opencode-anthropic-auth-dynamic/index.js"]
}
```

## Auth Methods

- **Claude Pro/Max** - OAuth with your existing subscription
- **API Key** - Generate or enter manually

## Why This Exists

This plugin exists because Anthropic blocks their API from working with OpenCode. These workarounds wouldn't be necessary if Anthropic allowed their paying customers to use better tools like OpenCode freely.

## License

MIT
