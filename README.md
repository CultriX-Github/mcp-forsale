# 🏷️ For-Sale MCP Server (Cloudflare Worker)

A lightweight **Model Context Protocol (MCP)** server that lets clients check whether a domain name advertises itself as **for sale** using the standardized [`_for-sale` DNS TXT record](https://datatracker.ietf.org/doc/html/draft-davids-forsalereg).

The server runs entirely on **Cloudflare Workers**, making it globally available, serverless, and free to operate at scale.

---

## ✨ What’s new

* **Built-in, fail-closed validator (server-side):**
  Every resolver tool now **always** runs a strict validator for `_for-sale` TXT records and returns a normalized **validator report**. No client/system prompt required; logic is enforced in the Worker.

* **Deterministic JSON schema:**
  The validator outputs a fixed JSON shape with `valid`, `errors[]`, `record_info`, `parsed`, and `explanations` (with per-rule pass/fail). It applies single-string TXT, exact version prefix, exactly one tag, decoding policy, URI allowlist, IDNA, and tag-specific rules.

* **IDNA (punycode) support for `furi` hosts:**
  Validator reports both Unicode and punycode host forms.

* **New tools:**

  * `validate_for_sale_txt` (low-level: validate a single TXT RDATA you already resolved)
  * `resolve_and_validate_for_sale` (one-shot: resolve + validate)

All existing tools (`check_for_sale`, `check_for_sale_structured`, `natural_language_check`) now **return validation results** alongside resolver output.

---

## ✨ Features

* **Implements the `_for-sale` draft specification**
  Parses `v=FORSALE1;` TXT records and extracts structured content fields (`furi`, `ftxt`, `fval`, `fcod`).

* **Strict, fail-closed validation**

  * Exact prefix: `v=FORSALE1;`
  * Exactly one tag from `{fcod, ftxt, furi, fval}`
  * TXT RDATA must be a **single character-string ≤255 octets** (no concatenation)
  * Unknown/additional tags (including via decoding) → reject
  * Decoding policy: **at most one** percent-decode pass and **only** for `furi`
  * `furi` must be **absolute** and scheme must be allowlisted (`https`, optional `http`, `mailto`, `tel`), length ≤2048 after decoding
  * Hostnames in `furi`: IDNA applied and both Unicode and punycode reported
  * `fcod`: `^[A-Z0-9_-]+$`, ≤32 chars
  * `ftxt`: opaque, ≤2048 chars, never decoded or linkified
  * `fval`: `^[A-Z]{3}[0-9]+(?:\.[0-9]{1,18})?$` → canonicalized as `"CUR amount"`
  * Aliases/wildcards: cross-zone heuristic & notes included
  * Returns **only JSON**; values are tainted and must be HTML-escaped downstream

* **Public MCP interface (SSE + Streamable HTTP)**
  Works with any MCP client (Claude Desktop, Cursor, Windsurf, MCP Inspector).

* **Natural-language querying**
  Provide prompts like “Is example.nl for sale?” — domain is extracted, resolved, and **validated** automatically.

* **Dual resolver support**

  * Default: [Cloudflare DoH JSON](https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/)
  * Optional: custom JSON resolver endpoint (`resolver.j78workers.workers.dev`)

* **Runs serverlessly on Cloudflare Workers** — no backend needed.

---

## 🧠 Background

This project implements the operational convention described in:

> **Davids, M. (2025)** —
> *The `_for-sale` Underscored and Globally Scoped DNS Node Name* — IETF Internet-Draft: `draft-davids-forsalereg-11`

It enables a domain holder to signal sale availability through DNS itself, without third-party marketplaces or WHOIS scraping.

---

## 🧰 Tools Exposed

Each resolver tool now returns **both** the classic resolver data and an array of **validator reports**:

Top-level (resolver) fields:

* `domain`: the queried registrable name
* `queried_name`: `_for-sale.<domain>`
* `method`: `"doh"` or `"resolver"`
* `is_for_sale`: basic presence check (any `v=FORSALE1;` TXT found)
* `records`: the raw TXT strings that begin with `v=FORSALE1;`
* `all_txt`: all TXT payloads found under the node
* `structured`: lenient extraction summary (pre-validator)
* `raw`: full DNS/resolver payload
* **`validations`: array of validator outputs (one per `records[i]`)**

### 1) Tool: `check_for_sale`

**Description:** Resolve `_for-sale.<domain>` and **always** validate any discovered `v=FORSALE1;` records.
**Example:** `{"domain": "example.nl", "method": "doh"}`

### 2) Tool: `check_for_sale_structured`

**Description:** Same as above; returns the same resolver data plus `validations` (and the `structured` summary).
**Example:** `{"domain": "example.nl"}`

### 3) Tool: `natural_language_check`

**Description:** Accepts a free-text prompt, extracts a domain, resolves and **validates**.
**Example:** `{"prompt": "Is example.nl for sale?"}`

### 4) Tool: `resolve_and_validate_for_sale`

**Description:** One-shot “resolve + validate” convenience endpoint.
**Example:** `{"domain": "example.nl", "method": "doh"}`

### 5) Tool: `validate_for_sale_txt`

**Description:** Low-level validator for a **single** TXT RDATA you already have (e.g., from your own resolver).
**Example input shape:**

```json
{
  "input": {
    "query_fqdn": "_for-sale.example.org.",
    "final_fqdn": "_for-sale.example.org.",
    "alias_chain": [],
    "is_wildcard": false,
    "rdata_len_bytes": 96,
    "txt": "v=FORSALE1;furi=https://broker.example/offer?id=123%2D456"
  }
}
```

---

## ✅ Validator Output Schema

Validator returns **only** JSON in this exact shape:

```json
{
  "valid": true,
  "errors": [],
  "record_info": {
    "query_fqdn": "string",
    "final_fqdn": "string",
    "cross_zone": false,
    "is_wildcard": false,
    "alias_chain": ["string"]
  },
  "parsed": {
    "tag": "fcod|ftxt|furi|fval",
    "value_raw": "string",
    "value_norm": "string|null",
    "extras": {
      "uri": {
        "scheme": "string|null",
        "host_unicode": "string|null",
        "host_punycode": "string|null",
        "path": "string|null",
        "query": "string|null"
      },
      "price": {
        "currency": "string|null",
        "amount_decimal": "string|null"
      }
    }
  },
  "explanations": {
    "summary": "string",
    "rule_evaluations": [
      {
        "rule": "string",
        "status": "pass|fail|not_applicable",
        "why": "string"
      }
    ]
  }
}
```

### Example A — Valid `furi` (https)

```json
{
  "valid": true,
  "errors": [],
  "record_info": {
    "query_fqdn": "_for-sale.example.org.",
    "final_fqdn": "_for-sale.example.org.",
    "cross_zone": false,
    "is_wildcard": false,
    "alias_chain": []
  },
  "parsed": {
    "tag": "furi",
    "value_raw": "https://broker.example/offer?id=123%2D456",
    "value_norm": "https://broker.example/offer?id=123-456",
    "extras": {
      "uri": {
        "scheme": "https",
        "host_unicode": "broker.example",
        "host_punycode": "broker.example",
        "path": "/offer",
        "query": "id=123-456"
      },
      "price": { "currency": null, "amount_decimal": null }
    }
  },
  "explanations": {
    "summary": "Record is valid: correct version prefix, exactly one allowed tag, absolute https URI with single percent-decoding, and no aliasing concerns.",
    "rule_evaluations": [
      {"rule": "prefix v=FORSALE1;", "status": "pass", "why": "String begins with exact prefix."},
      {"rule": "exactly one tag", "status": "pass", "why": "Only 'furi=' found after prefix."},
      {"rule": "single-string ≤255 octets", "status": "pass", "why": "Length within limit; single character-string."},
      {"rule": "URI scheme allowlist", "status": "pass", "why": "Scheme is https (allowlisted)."},
      {"rule": "at most one percent-decoding (furi only)", "status": "pass", "why": "Decoded %2D to '-' once; no further decoding applied."},
      {"rule": "absolute URL required", "status": "pass", "why": "URI includes scheme and authority."},
      {"rule": "aliases/wildcards cross-zone check", "status": "pass", "why": "No cross-zone detected."}
    ]
  }
}
```

### Example B — Invalid: disallowed scheme

```json
{
  "valid": false,
  "errors": ["furi scheme not allowed"],
  "record_info": {
    "query_fqdn": "_for-sale.example.org.",
    "final_fqdn": "_for-sale.example.org.",
    "cross_zone": false,
    "is_wildcard": false,
    "alias_chain": []
  },
  "parsed": null,
  "explanations": {
    "summary": "Invalid: the URI uses a non-allowlisted scheme which is explicitly rejected for security.",
    "rule_evaluations": [
      {"rule": "prefix v=FORSALE1;", "status": "pass", "why": "Prefix is present."},
      {"rule": "URI scheme allowlist", "status": "fail", "why": "Scheme 'javascript' is excluded."}
    ]
  }
}
```

---

## 🧪 Example Resolver Output (now with validations)

```json
{
  "domain": "example.nl",
  "queried_name": "_for-sale.example.nl",
  "method": "doh",
  "is_for_sale": true,
  "records": [
    "v=FORSALE1;furi=https://broker.example/offer?id=123%2D456"
  ],
  "structured": {
    "furi": ["https://broker.example/offer?id=123%2D456"]
  },
  "validations": [
    {
      "valid": true,
      "errors": [],
      "record_info": {
        "query_fqdn": "_for-sale.example.nl.",
        "final_fqdn": "_for-sale.example.nl.",
        "cross_zone": false,
        "is_wildcard": false,
        "alias_chain": []
      },
      "parsed": {
        "tag": "furi",
        "value_raw": "https://broker.example/offer?id=123%2D456",
        "value_norm": "https://broker.example/offer?id=123-456",
        "extras": {
          "uri": {
            "scheme": "https",
            "host_unicode": "broker.example",
            "host_punycode": "broker.example",
            "path": "/offer",
            "query": "id=123-456"
          },
          "price": { "currency": null, "amount_decimal": null }
        }
      },
      "explanations": { "summary": "Record is valid...", "rule_evaluations": [/* … */] }
    }
  ]
}
```

---

## 🚀 Deployment

### 1) Clone and install

```bash
git clone https://github.com/<yourname>/mcp-forsale-server.git
cd mcp-forsale-server
npm install
# If you forked: ensure dependency "punycode" is present (used by validator for IDNA)
```

### 2) Develop locally

```bash
npm start
```

This runs the Worker at `http://127.0.0.1:8788`.

MCP endpoints:

* **SSE:** `http://127.0.0.1:8788/sse`
* **HTTP:** `http://127.0.0.1:8788/mcp`

Test locally using MCP Inspector:

```bash
npx @modelcontextprotocol/inspector
# → open http://localhost:5173, connect to http://127.0.0.1:8788/sse
```

### 3) Deploy to Cloudflare

```bash
npx wrangler deploy
```

Public endpoints:

* **SSE:** `https://my-mcp-forsale.j78workers.workers.dev/sse`
* **HTTP:** `https://my-mcp-forsale.j78workers.workers.dev/mcp`

### 🔍 Testing the Public Endpoint

**Basic availability:**

```bash
curl -i https://my-mcp-forsale.j78workers.workers.dev/sse
```

**Interactive (recommended):**

```bash
npx @modelcontextprotocol/inspector
# connect → https://my-mcp-forsale.j78workers.workers.dev/sse
```

**CLI (lightweight adapter):**

```bash
npx mcp-remote https://my-mcp-forsale.j78workers.workers.dev/sse
```

Inside the REPL:

```text
/tools
/call check_for_sale_structured {"domain":"example.nl"}
```

---

## ⚙️ Configuration

*(These can be added to `wrangler.toml` or Worker secrets if desired.)*

### 1) Env: `FORSALE_QUERY_METHOD`

* **Purpose:** Preferred resolver: `"doh"` or `"resolver"`
* **Default:** `"doh"`

### 2) Env: `CORS_ALLOWED_ORIGINS`

* **Purpose:** Optional list of allowed origins for browser MCP clients
* **Default:** `*`

---

## 🧩 MCP Client Notes

* You **cannot** push a system prompt from an MCP server into the client’s LLM.
  This Worker enforces validation **server-side** and returns deterministic JSON, so clients don’t need to trust prompts.

### Claude Desktop example

Create or edit `~/.config/Claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "forSaleChecker": {
      "command": "npx",
      "args": ["mcp-remote", "https://my-mcp-forsale.j78workers.workers.dev/sse"]
    }
  }
}
```

Restart Claude Desktop. You’ll see tools:
`check_for_sale`, `check_for_sale_structured`, `natural_language_check`, `resolve_and_validate_for_sale`, `validate_for_sale_txt`.

If you later protect your Worker with a token or Cloudflare Access, add the appropriate headers in your proxy or use the client’s native remote-MCP configuration to supply `Authorization`.

---

## 🛡️ Security / Privacy

* No user data is stored.
* All DNS queries are public via DoH or your configured resolver.
* The Worker can be fronted by Cloudflare Access or require `Authorization: Bearer <token>`.

---

## 🧑‍💻 Author

**Jesse** — Nijmegen, Netherlands

---

## 📄 License

**MIT License © 2025 Jesse**

This project builds on concepts described in the public IETF Internet-Draft `draft-davids-forsalereg-11`.

---

## Example live instance

`https://my-mcp-forsale.j78workers.workers.dev/sse`

*Accessible from any compliant MCP client. Happy hacking — and may your domains sell swiftly! 🪩*

