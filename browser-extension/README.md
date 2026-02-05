# In-A-Lign Browser Extension

AI Security + Efficiency for Claude.ai, ChatGPT, and more.

## Features

- **🛡️ Injection Detection**: Blocks prompt injection attacks in real-time
- **🔒 PII Masking**: Automatically masks personal information before sending
- **📊 Token Counter**: Shows estimated token count for your messages
- **🌍 Multi-language**: Supports English, Korean, Japanese, Chinese, Spanish, French

## Supported Sites

- Claude.ai
- ChatGPT (chat.openai.com)
- Google Gemini

## Installation

### Chrome

1. Open `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the `browser-extension` folder

### Firefox

1. Open `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select `manifest.json` from the `browser-extension` folder

## Usage

1. Install the extension
2. Navigate to Claude.ai or ChatGPT
3. The extension automatically protects your conversations
4. Click the extension icon to view stats and settings

## Settings

- **Security Check**: Enable/disable injection detection
- **PII Auto-Mask**: Automatically mask personal information
- **Token Counter**: Show token count on input

## How It Works

```
User Input → In-A-Lign Checks → Safe? → Send to AI
                ↓
            Blocked? → Show Warning
                ↓
            PII Found? → Mask & Warn
```

## Icon Generation

To generate PNG icons from the SVG:

```bash
# Using ImageMagick
convert icons/icon.svg -resize 16x16 icons/icon16.png
convert icons/icon.svg -resize 48x48 icons/icon48.png
convert icons/icon.svg -resize 128x128 icons/icon128.png
```

Or use any SVG to PNG converter online.

## Development

```bash
# Watch for changes (if using build tools)
npm run watch

# Package for distribution
npm run build
```

## License

MIT License - In-A-Lign
