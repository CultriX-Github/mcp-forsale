
# 🏷️ For-Sale MCP Server (Cloudflare Worker)

A lightweight **Model Context Protocol (MCP)** server that lets clients check whether a domain name advertises itself as **for sale** using the standardized [`_for-sale` DNS TXT record](https://datatracker.ietf.org/doc/html/draft-davids-forsalereg "null").

The server runs entirely on **Cloudflare Workers**, making it globally available, serverless, and free to operate at scale.

## ✨ Features

-   **Implements the `_for-sale` draft specification** Parses `v=FORSALE1;` TXT records and extracts structured content fields (`furi`, `ftxt`, `fval`, `fcod`).
    
-   **Public MCP interface (SSE + Streamable HTTP)** Works with any MCP-compliant client such as Claude Desktop, Cursor, Windsurf, or the [MCP Inspector](https://github.com/modelcontextprotocol/inspector "null").
    
-   **Natural-language querying** Accepts human prompts like
    
    > “Is example.nl for sale?”
    
    > and automatically extracts and checks the domain.
    
-   **Dual resolver support** - Default: [Cloudflare DNS-over-HTTPS (DoH)](https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/ "null")
    
    -   Optional: custom JSON resolver endpoint (`resolver.j78workers.workers.dev`).
        
-   **Runs serverlessly on Cloudflare Workers** — no backend needed.
    

## 🧠 Background

This project implements the operational convention described in:

> **Davids, M. (2025)** —
> 
> _The `_for-sale` Underscored and Globally Scoped DNS Node Name_ > [IETF Internet-Draft: draft-davids-forsalereg-11](https://datatracker.ietf.org/doc/html/draft-davids-forsalereg "null")

It enables a domain holder to signal sale availability through DNS itself, without third-party marketplaces or WHOIS scraping.

## 🧰 Tools Exposed

### 1. Tool: `check_for_sale`
#### Description: Checks whether `_for-sale.<domain>` exists and returns basic results.
#### Example: `{"domain": "example.nl", "method": "doh"}`

### 2. Tool: `check_for_sale_structured`
#### Description: Returns parsed structured fields (`furi`, `ftxt`, `fval`, `fcod`, etc.).
#### Example: `{"domain": "example.nl"}`

### 3. Tool: `natural_language_check`
#### Description: Accepts a free-text prompt and automatically detects the domain.
#### Example: `{"prompt": "Is example.nl for sale?"}`

Each tool outputs JSON containing:

-   `is_for_sale`: boolean
    
-   `records`: valid TXT strings beginning with `v=FORSALE1;`
    
-   `structured`: object of extracted tag values
    
-   `raw`: full DNS or resolver output
    

## 🚀 Deployment

### 1. Clone and install

```
git clone [https://github.com/](https://github.com/)<yourname>/mcp-forsale-server.git
cd mcp-forsale-server
npm install

```

### 2. Develop locally

```
npm start

```

This runs the Worker at `http://127.0.0.1:8788`.

The MCP endpoints will be:

-   **SSE:** `http://127.0.0.1:8788/sse`
    
-   **HTTP:** `http://127.0.0.1:8788/mcp`
    

You can test locally using MCP Inspector:

```
npx @modelcontextprotocol/inspector
# → open http://localhost:5173, connect to [http://127.0.0.1:8788/sse](http://127.0.0.1:8788/sse)

```

### 3. Deploy to Cloudflare

```
npx wrangler deploy

```

Your public endpoints will be:

-   **SSE:** `https://my-mcp-forsale.j78workers.workers.dev/sse`
    
-   **HTTP:** `https://my-mcp-forsale.j78workers.workers.dev/mcp`
    

### 🔍 Testing the Public Endpoint

**Basic availability:**

```
curl -i [https://my-mcp-forsale.j78workers.workers.dev/sse](https://my-mcp-forsale.j78workers.workers.dev/sse)

```

**Interactive (recommended):**

```
npx @modelcontextprotocol/inspector
# connect → [https://my-mcp-forsale.j78workers.workers.dev/sse](https://my-mcp-forsale.j78workers.workers.dev/sse)

```

**CLI (lightweight adapter):**

```
npx mcp-remote [https://my-mcp-forsale.j78workers.workers.dev/sse](https://my-mcp-forsale.j78workers.workers.dev/sse)

```

Inside the REPL:

```
/tools
/call check_for_sale_structured {"domain":"example.nl"}

```

### ⚙️ Configuration

Env variable

Purpose

Default

`FORSALE_QUERY_METHOD`

Preferred resolver: "doh" or "resolver"

"doh"

`CORS_ALLOWED_ORIGINS`

Optional list of allowed origins for browser MCP clients

`*`

_(These can be added to `wrangler.toml` or Worker secrets if desired.)_

### 🧩 Claude Desktop configuration (example)

Create or edit `~/.config/Claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows), and add:

```
{
  "mcpServers": {
    "forSaleChecker": {
      "command": "npx",
      "args": ["mcp-remote", "[https://my-mcp-forsale.j78workers.workers.dev/sse](https://my-mcp-forsale.j78workers.workers.dev/sse)"]
    }
  }
}

```

Restart Claude Desktop. You’ll see a connector named `forSaleChecker` with tools: `check_for_sale`, `check_for_sale_structured`, and `natural_language_check`.

If you later protect your Worker with a token or Cloudflare Access, add the appropriate headers in your proxy or switch to Claude’s native remote-MCP configuration UI where you can supply an `Authorization` header.

### 🧪 Example Output

```
{
  "domain": "example.nl",
  "queried_name": "_for-sale.example.nl",
  "method": "doh",
  "is_for_sale": true,
  "records": [
    "v=FORSALE1;fcod=NLFS-NGYyYjEyZWYtZTUzYi00M2U0LTliNmYtNTcxZjBhMzA2NWQy",
    "v=FORSALE1;ftxt=See the URL for important information!",
    "v=FORSALE1;furi=[https://example.nl/for-sale.txt](https://example.nl/for-sale.txt)"
  ],
  "structured": {
    "fcod": ["NLFS-NGYyYjEyZWYtZTUzYi00M2U0LTliNmYtNTcxZjBhMzA2NWQy"],
    "ftxt": ["See the URL for important information!"],
    "furi": ["[https://example.nl/for-sale.txt](https://example.nl/for-sale.txt)"]
  }
}

```

### 🛡️ Security / Privacy

-   No user data is stored.
    
-   All DNS queries are public via DoH.
    
-   The Worker can optionally be fronted by Cloudflare Access or require an `Authorization: Bearer <token>` header for private usage.
    

### 🧩 Integration

**Claude Desktop or other MCP clients**

Add a **Custom Connector** → **URL**: `https://my-mcp-forsale.j78workers.workers.dev/sse`

**Transport:** `SSE`

(Optional) Add headers like `Authorization: Bearer <token>`

Restart and invoke the tools directly from chat.

### 🧑‍💻 Author

**Jesse** — Nijmegen, Netherlands

### 📄 License

**MIT License © 2025 Jesse**

This project builds on concepts described in the public IETF Internet-Draft `draft-davids-forsalereg-11`.

### Example live instance

`https://my-mcp-forsale.j78workers.workers.dev/sse`

_Accessible from any compliant MCP client._

Happy hacking — and may your domains sell swiftly! 🪩
