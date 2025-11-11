import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

/* ---------------------- helpers & parsing logic ---------------------- */

const FORSALE_PREFIX = "v=FORSALE1;";

function normalizeTxtLines(lines: string[]): string[] {
  return lines
    .map((s) => s.trim())
    .map((s) =>
      s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s
    )
    .filter(Boolean);
}

function extractAfterVersion(record: string): string | null {
  if (!record.startsWith(FORSALE_PREFIX)) return null;
  return record.slice(FORSALE_PREFIX.length); // may be ""
}

function parseTagValue(content: string): { tag: string; value: string } | null {
  if (!content) return { tag: "", value: "" };
  const m = content.match(/^([a-z]{4})=(.*)$/);
  return m ? { tag: m[1], value: m[2] } : { tag: "", value: "" };
}

function parseFval(v: string): { currency?: string; amount?: string } {
  let m = v.match(/^([A-Z]{3,})\s*(\d+(?:\.\d+)?)\s*$/);
  if (m) return { currency: m[1], amount: m[2] };
  m = v.match(/^([A-Z]{3,})(\d+(?:\.\d+)?)$/);
  if (m) return { currency: m[1], amount: m[2] };
  return {};
}

function structuredParse(versioned: string[]) {
  const out = {
    fcod: [] as string[],
    ftxt: [] as string[],
    furi: [] as string[],
    fval: [] as string[],
    fval_parsed: [] as { currency: string; amount: string }[],
    unknown_tags: [] as { tag: string; value: string }[],
  };
  for (const rec of versioned) {
    const content = extractAfterVersion(rec);
    if (content === null) continue;
    const tv = parseTagValue(content);
    if (!tv) continue;
    const { tag, value } = tv;
    if (tag === "fcod") out.fcod.push(value);
    else if (tag === "ftxt") out.ftxt.push(value);
    else if (tag === "furi") out.furi.push(value);
    else if (tag === "fval") {
      out.fval.push(value);
      const { currency, amount } = parseFval(value);
      if (currency && amount) out.fval_parsed.push({ currency, amount });
    } else if (tag === "") {
      // only version tag present, no content
    } else {
      out.unknown_tags.push({ tag, value });
    }
  }
  return out;
}

function isDomain(name: string): boolean {
  return /^[A-Za-z0-9.-]{1,253}$/.test(name) && name.includes(".");
}

function extractDomainFromPrompt(prompt: string): string | null {
  const re =
    /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi;
  const m = re.exec(prompt);
  if (!m) return null;
  let d = m[1].replace(/^_for-sale\./i, "");
  return isDomain(d) ? d : null;
}

async function queryTxtDoH(domain: string): Promise<{ raw: any; txt: string[] }> {
  const qname = `_for-sale.${domain}`;
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
    qname
  )}&type=TXT`;
  const resp = await fetch(url, { headers: { Accept: "application/dns-json" } });
  const json = await resp.json();
  const answers: string[] =
    json?.Answer?.map((a: any) => (typeof a?.data === "string" ? a.data : "")) ??
    [];
  const txt = normalizeTxtLines(answers);
  return { raw: json, txt };
}

async function queryTxtResolver(
  domain: string
): Promise<{ raw: any; txt: string[] }> {
  const qname = `_for-sale.${domain}`;
  const url = `https://resolver.j78workers.workers.dev/${qname}/TXT.json`;
  const resp = await fetch(url);
  let raw: any;
  try {
    raw = await resp.json();
  } catch {
    raw = await resp.text();
  }
  let candidates: string[] = [];
  if (raw && typeof raw === "object") {
    if (Array.isArray(raw.Answer))
      candidates.push(...raw.Answer.map((x: any) => String(x)));
    if (Array.isArray(raw.answers))
      candidates.push(...raw.answers.map((x: any) => String(x)));
    if (Array.isArray(raw.records)) {
      for (const r of raw.records) if (r && r.data) candidates.push(String(r.data));
    }
  }
  const txt = candidates.length
    ? normalizeTxtLines(candidates)
    : normalizeTxtLines(String(raw).split("\n"));
  return { raw, txt };
}

function verdict(txt: string[]) {
  const versioned = txt.filter((s) => s.startsWith(FORSALE_PREFIX));
  return { is_for_sale: versioned.length > 0, versioned };
}

async function runQuery(
  domain: string,
  method: "doh" | "resolver" = "doh"
) {
  const { raw, txt } =
    method === "resolver" ? await queryTxtResolver(domain) : await queryTxtDoH(domain);
  const v = verdict(txt);
  const structured = structuredParse(v.versioned);
  return {
    domain,
    queried_name: `_for-sale.${domain}`,
    method,
    is_for_sale: v.is_for_sale,
    records: v.versioned,
    all_txt: txt,
    structured,
    raw,
  };
}

/* ----------------------------- MCP server ---------------------------- */

export class MyMCP extends McpAgent {
  server = new McpServer({
    name: "ForSale Checker",
    version: "1.0.0",
  });

  async init() {
    // 1) Simple presence check
    this.server.tool(
      "check_for_sale",
      {
        domain: z.string(),
        method: z.enum(["doh", "resolver"]).default("doh"),
      },
      async ({ domain, method }) => {
        if (!isDomain(domain)) {
          return {
            content: [
              { type: "text", text: JSON.stringify({ error: "Invalid domain" }) },
            ],
          };
        }
        const res = await runQuery(domain, method);
        return {
          content: [{ type: "text", text: JSON.stringify(res) }],
        };
      }
    );

    // 2) Structured extraction (same result, explicitly documented)
    this.server.tool(
      "check_for_sale_structured",
      {
        domain: z.string(),
        method: z.enum(["doh", "resolver"]).default("doh"),
      },
      async ({ domain, method }) => {
        if (!isDomain(domain)) {
          return {
            content: [
              { type: "text", text: JSON.stringify({ error: "Invalid domain" }) },
            ],
          };
        }
        const res = await runQuery(domain, method);
        return {
          content: [{ type: "text", text: JSON.stringify(res) }],
        };
      }
    );

    // 3) Natural language interface
    this.server.tool(
      "natural_language_check",
      {
        prompt: z.string(),
      },
      async ({ prompt }) => {
        if (!prompt || !prompt.trim()) {
          return {
            content: [
              { type: "text", text: JSON.stringify({ error: "Empty prompt" }) },
            ],
          };
        }
        const domain = extractDomainFromPrompt(prompt);
        if (!domain) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: "No domain found in prompt" }),
              },
            ],
          };
        }
        // Default to DOH; switch to resolver when user hints at dig/resolver/curl
        const method = /\b(dig|resolver|curl)\b/i.test(prompt) ? "resolver" : "doh";
        const res = await runQuery(domain, method);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ ...res, interpreted_from_prompt: true }),
            },
          ],
        };
      }
    );
  }
}

/* --------------------------- Worker endpoints ------------------------- */

export default {
  fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/sse" || url.pathname === "/sse/message") {
      return MyMCP.serveSSE("/sse").fetch(request, env, ctx);
    }

    if (url.pathname === "/mcp") {
      return MyMCP.serve("/mcp").fetch(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
};

