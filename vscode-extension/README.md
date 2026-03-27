# NAIL AVE Browser — VS Code Extension

Browse and search the [NAIL Institute](https://nailinstitute.org) Agentic
Vulnerability Enumeration (AVE) database directly from VS Code.

![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-007ACC?logo=visual-studio-code)

## Features

- **Tree View** — Browse all 100 AVE cards grouped by category or severity
- **Search** — Full-text search across card names, summaries, MITRE mappings
- **Card Details** — Rich webview showing full card information
- **MITRE Links** — One-click navigation to MITRE ATT&CK/ATLAS technique pages
- **Severity Icons** — Visual indicators for critical/high/medium vulnerabilities

## Installation

```bash
cd vscode-extension
npm install
npm run compile
```

Then press `F5` to launch the Extension Development Host.

### From VSIX

```bash
npm run package
code --install-extension nail-ave-browser-0.1.0.vsix
```

## Usage

1. Click the **AVE Database** icon in the Activity Bar
2. Click **Refresh** to load cards from the API
3. Browse by category or severity
4. Click any card to see full details
5. Use `Ctrl+Shift+P` → "AVE: Search AVE Cards" to search

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `ave.apiUrl` | `https://api.nailinstitute.org` | API endpoint |
| `ave.showSeverityIcons` | `true` | Show severity icons |
| `ave.autoRefresh` | `false` | Auto-refresh on activation |

## Development

```bash
npm install
npm run watch     # Compile in watch mode
# Press F5 to launch Extension Development Host
```

## License

MIT — [NAIL Institute](https://nailinstitute.org)
