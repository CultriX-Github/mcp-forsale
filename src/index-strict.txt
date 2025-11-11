import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import punycode from "punycode/";

/* ---------------------- helpers & parsing logic ---------------------- */

const FORSALE_PREFIX = "v=FORSALE1;";
const MAX_TXT_LEN = 255;

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
    json?.Answer?.map((a: any) => (typeof a?.data === "string" ? a.data : "")) ?? [];
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

/* ---------------------- FOR-SALE TXT VALIDATOR ----------------------- */

type ValidatorInput = {
  query_fqdn: string;
  final_fqdn: string;
  alias_chain: string[];
  is_wildcard: boolean;
  rdata_len_bytes: number;
  txt: string;
};

type RuleEval = { rule: string; status: "pass" | "fail" | "not_applicable"; why: string };

const ALLOWED_SCHEMES = new Set(["https", "http", "mailto", "tel"]);

function trimOuterQuotesOnce(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}

function isSingleStringRdata(lenBytes: number, txt: string): boolean {
  return lenBytes <= MAX_TXT_LEN && !/\\"\s*\\"/.test(txt);
}

function tokenizeAfterPrefix(s: string): { tag: string; value: string } | null {
  const rest = s.slice(FORSALE_PREFIX.length);
  const m = rest.match(/^([a-z]{4})=(.*)$/);
  if (!m) return null;
  if (m[2].includes(";")) return null;
  return { tag: m[1], value: m[2] };
}

function idnaPair(host: string) {
  if (!host) return { host_unicode: null, host_punycode: null };
  const ascii = punycode.toASCII(host);
  const uni = punycode.toUnicode(ascii);
  return {
    host_unicode: uni || null,
    host_punycode: ascii || null,
  };
}

function decodeURIComponentSafeOnce(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function parseAbsoluteUriOnce(valueRaw: string) {
  const onceDecoded = decodeURIComponentSafeOnce(valueRaw);
  let valueNorm = onceDecoded;
  let url: URL | null = null;
  try {
    url = new URL(valueNorm);
  } catch {
    url = null;
  }
  return { valueNorm, url };
}

function allowedScheme(u: URL | null): { ok: boolean; scheme: string | null } {
  if (!u) return { ok: false, scheme: null };
  const scheme = u.protocol.replace(":", "");
  return { ok: ALLOWED_SCHEMES.has(scheme), scheme };
}

function uriLengthOk(s: string): boolean {
  return s.length <= 2048;
}

function fcodOk(v: string): boolean {
  return /^[A-Z0-9_-]{1,32}$/.test(v);
}

function fvalOk(v: string) {
  const m = v.match(/^([A-Z]{3})([0-9]+(?:\.[0-9]{1,18})?)$/);
  if (!m) return null;
  return { currency: m[1], amount: m[2] };
}

function ftxtOk(v: string) {
  return v.length <= 2048;
}

function sameRegistrableHeuristic(a: string, b: string): boolean {
  const split = (x: string) => x.replace(/\.$/, "").toLowerCase().split(".");
  const al = split(a);
  const bl = split(b);
  const a2 = al.slice(-2).join(".");
  const b2 = bl.slice(-2).join(".");
  return a2 === b2;
}

function makeBaseOutput(input: ValidatorInput) {
  return {
    valid: false,
    errors: [] as string[],
    record_info: {
      query_fqdn: input.query_fqdn,
      final_fqdn: input.final_fqdn,
      cross_zone: !sameRegistrableHeuristic(input.query_fqdn, input.final_fqdn),
      is_wildcard: input.is_wildcard,
      alias_chain: input.alias_chain || [],
    },
    parsed: null as any,
    explanations: {
      summary: "",
      rule_evaluations: [] as RuleEval[],
    },
  };
}

export function validateForSaleTXT(input: ValidatorInput) {
  const out = makeBaseOutput(input);
  const rules: RuleEval[] = out.explanations.rule_evaluations;

  const rawTxtOriginal = input.txt;
  const txt = trimOuterQuotesOnce(rawTxtOriginal).trim();

  // Rule: single-string ≤255 octets
  const single = isSingleStringRdata(input.rdata_len_bytes, rawTxtOriginal);
  rules.push({
    rule: "single-string ≤255 octets",
    status: single ? "pass" : "fail",
    why: single
      ? `Length reported as ${input.rdata_len_bytes} bytes; no multi-string concatenation detected.`
      : `Reported length ${input.rdata_len_bytes} exceeds 255 or multi-string concatenation detected.`,
  });
  if (!single) out.errors.push("TXT RDATA must be a single character-string ≤255 octets");

  // Rule: prefix
  const hasPrefix = txt.startsWith(FORSALE_PREFIX);
  rules.push({
    rule: "prefix v=FORSALE1;",
    status: hasPrefix ? "pass" : "fail",
    why: hasPrefix ? "String begins with exact prefix." : "Prefix missing or not exact.",
  });
  if (!hasPrefix) out.errors.push("record must start with exact v=FORSALE1;");

  // Tokenize after prefix -> exactly one tag=value
  let tag: string | null = null;
  let valueRaw: string | null = null;
  if (hasPrefix) {
    const tv = tokenizeAfterPrefix(txt);
    if (tv) {
      tag = tv.tag;
      valueRaw = tv.value;
      rules.push({
        rule: "exactly one tag",
        status: "pass",
        why: `Only '${tag}=' found after prefix.`,
      });
    } else {
      rules.push({
        rule: "exactly one tag",
        status: "fail",
        why: "Missing or multiple tags detected (extra ';' or no tag=value).",
      });
      out.errors.push("record must contain exactly one tag");
    }
  } else {
    rules.push({
      rule: "exactly one tag",
      status: "not_applicable",
      why: "Prefix check failed.",
    });
  }

  // Unknown/additional tags cause rejection
  const allowedTag = tag && ["fcod", "ftxt", "furi", "fval"].includes(tag);
  if (tag) {
    rules.push({
      rule: "allowed tag",
      status: allowedTag ? "pass" : "fail",
      why: allowedTag ? "Tag is in {fcod, ftxt, fval, furi}." : `Unknown tag '${tag}'.`,
    });
    if (!allowedTag) out.errors.push("unknown or disallowed tag");
  } else {
    rules.push({ rule: "allowed tag", status: "not_applicable", why: "No tag parsed." });
  }

  // Tag-specific validation
  let valueNorm: string | null = null;
  let uriExtras: any = {
    scheme: null,
    host_unicode: null,
    host_punycode: null,
    path: null,
    query: null,
  };
  let priceExtras: any = { currency: null, amount_decimal: null };

  if (allowedTag && valueRaw !== null) {
    if (tag === "furi") {
      // decoding policy: one pass only
      const { valueNorm: vNorm, url } = parseAbsoluteUriOnce(valueRaw);
      valueNorm = vNorm;

      // refuse to recover additional tags via decoding
      if (vNorm.includes(";") && /[?&;]([a-z]{4})=/.test(vNorm)) {
        out.errors.push("refused to recover additional tags via decoding");
        rules.push({
          rule: "decoding policy",
          status: "pass",
          why: "Applied one percent-decoding pass only to furi; did not treat decoded content as new tags.",
        });
      } else {
        rules.push({
          rule: "decoding policy",
          status: "pass",
          why: "Applied at most one percent-decoding to furi.",
        });
      }

      // absolute URL required
      const absoluteOk = !!url && !!url.host && !!url.protocol;
      rules.push({
        rule: "absolute URL required",
        status: absoluteOk ? "pass" : "fail",
        why: absoluteOk ? "URL includes scheme and authority." : "Not an absolute URL.",
      });
      if (!absoluteOk) out.errors.push("furi must be an absolute URI");

      // scheme allowlist
      const { ok: schemeOk, scheme } = allowedScheme(url || null);
      rules.push({
        rule: "URI scheme allowlist",
        status: schemeOk ? "pass" : "fail",
        why: schemeOk ? `Scheme is ${scheme} (allowlisted).` : `Scheme '${scheme ?? "unknown"}' is not allowlisted.`,
      });
      if (!schemeOk) out.errors.push("furi scheme not allowed");

      // enforce max URI length after decoding
      const lenOk = uriLengthOk(valueNorm);
      rules.push({
        rule: "max URI length ≤2048",
        status: lenOk ? "pass" : "fail",
        why: lenOk ? `Length ${valueNorm.length} within limit.` : `Length ${valueNorm.length} exceeds 2048.`,
      });
      if (!lenOk) out.errors.push("furi exceeds maximum length");

      // IDNA host report
      const { host_unicode, host_punycode } = idnaPair(url ? url.hostname : "");
      uriExtras = {
        scheme: url ? url.protocol.replace(":", "") : null,
        host_unicode,
        host_punycode,
        path: url ? url.pathname || "/" : null,
        query: url ? (url.search ? url.search.slice(1) : null) : null,
      };
    }

    if (tag === "fcod") {
      const ok = fcodOk(valueRaw);
      rules.push({
        rule: "fcod charset/length",
        status: ok ? "pass" : "fail",
        why: ok ? "Only [A-Z0-9_-], ≤32 chars." : "Value violates charset and/or length.",
      });
      if (!ok) out.errors.push("fcod invalid format");
      valueNorm = null;
      rules.push({
        rule: "percent-decoding (non-furi)",
        status: "pass",
        why: "No decoding applied to non-furi tags.",
      });
    }

    if (tag === "ftxt") {
      const ok = ftxtOk(valueRaw);
      rules.push({
        rule: "ftxt length ≤2048",
        status: ok ? "pass" : "fail",
        why: ok ? "Opaque text within limit." : "Text exceeds 2048 chars.",
      });
      if (!ok) out.errors.push("ftxt too long");
      valueNorm = null;
      rules.push({ rule: "never linkify", status: "pass", why: "Value treated as opaque text; no linkification performed." });
      rules.push({
        rule: "percent-decoding (non-furi)",
        status: "pass",
        why: "No decoding applied to non-furi tags.",
      });
    }

    if (tag === "fval") {
      const parsed = fvalOk(valueRaw);
      const ok = !!parsed;
      rules.push({
        rule: "fval pattern",
        status: ok ? "pass" : "fail",
        why: ok ? "Matches ^[A-Z]{3}[0-9]+(\\.[0-9]{1,18})?$." : "Value does not match required pattern.",
      });
      if (!ok) out.errors.push("fval invalid format");
      rules.push({
        rule: "percent-decoding (non-furi)",
        status: "pass",
        why: "No decoding applied to non-furi tags.",
      });
      if (parsed) {
        priceExtras = { currency: parsed.currency, amount_decimal: parsed.amount };
        valueNorm = `${parsed.currency} ${parsed.amount}`;
      }
    }
  } else {
    rules.push({
      rule: "tag-specific validation",
      status: "not_applicable",
      why: "No allowed tag parsed.",
    });
  }

  // Aliases/wildcards assessment
  rules.push({
    rule: "aliases/wildcards cross-zone check",
    status: "pass",
    why: !sameRegistrableHeuristic(input.query_fqdn, input.final_fqdn)
      ? "Final TXT is under a different registrable domain (heuristic)."
      : "No cross-zone detected (heuristic).",
  });

  const okAll = out.errors.length === 0;
  out.valid = okAll;

  if (okAll) {
    out.parsed = {
      tag: (tokenizeAfterPrefix(trimOuterQuotesOnce(input.txt).trim()) as any).tag,
      value_raw: (tokenizeAfterPrefix(trimOuterQuotesOnce(input.txt).trim()) as any).value,
      value_norm: valueNorm,
      extras: {
        uri: uriExtras,
        price: priceExtras,
      },
    };
    out.explanations.summary =
      out.parsed.tag === "furi"
        ? "Record is valid: correct version prefix, exactly one allowed tag, absolute allowlisted URI with single percent-decoding, and no aliasing concerns."
        : "Record is valid: correct version prefix, exactly one allowed tag, value conforms to tag-specific rules, and no aliasing concerns.";
  } else {
    out.parsed = null;
    out.explanations.summary = out.errors.length
      ? `Invalid: ${out.errors.join("; ")}.`
      : "Invalid: one or more unspecified rules failed.";
  }

  return out;
}

/* -------- resolver + validator wiring (validation ALWAYS runs) -------- */

async function resolveAndValidate(domain: string, method: "doh" | "resolver") {
  const res = await runQuery(domain, method);

  // Build a validation result for each versioned record (strict, fail-closed)
  const validations = res.records.map((rec) =>
    validateForSaleTXT({
      query_fqdn: `${res.queried_name}.`,
      final_fqdn: `${res.queried_name}.`, // if you add alias chasing, update this and alias_chain
      alias_chain: [],
      is_wildcard: false,
      rdata_len_bytes: rec.length, // best available proxy when byte length not provided
      txt: rec,
    })
  );

  return { ...res, validations };
}

/* ----------------------------- MCP server ---------------------------- */

export class MyMCP extends McpAgent {
  server = new McpServer({
    name: "ForSale Checker",
    version: "1.1.0",
  });

  async init() {
    // 1) Presence + ALWAYS validate
    this.server.tool(
      "check_for_sale",
      {
        domain: z.string(),
        method: z.enum(["doh", "resolver"]).default("doh"),
      },
      async ({ domain, method }) => {
        if (!isDomain(domain)) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: "Invalid domain" }) }],
          };
        }
        const res = await resolveAndValidate(domain, method);
        return {
          content: [{ type: "text", text: JSON.stringify(res) }],
        };
      }
    );

    // 2) Structured extraction + ALWAYS validate
    this.server.tool(
      "check_for_sale_structured",
      {
        domain: z.string(),
        method: z.enum(["doh", "resolver"]).default("doh"),
      },
      async ({ domain, method }) => {
        if (!isDomain(domain)) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: "Invalid domain" }) }],
          };
        }
        const res = await resolveAndValidate(domain, method);
        return {
          content: [{ type: "text", text: JSON.stringify(res) }],
        };
      }
    );

    // 3) Natural language interface + ALWAYS validate
    this.server.tool(
      "natural_language_check",
      {
        prompt: z.string(),
      },
      async ({ prompt }) => {
        if (!prompt || !prompt.trim()) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: "Empty prompt" }) }],
          };
        }
        const domain = extractDomainFromPrompt(prompt);
        if (!domain) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: "No domain found in prompt" }) }],
          };
        }
        const method = /\b(dig|resolver|curl)\b/i.test(prompt) ? "resolver" : "doh";
        const res = await resolveAndValidate(domain, method);
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

    // 4) Low-level validator (run directly with a single TXT input)
    this.server.tool(
      "validate_for_sale_txt",
      {
        input: z.object({
          query_fqdn: z.string(),
          final_fqdn: z.string(),
          alias_chain: z.array(z.string()),
          is_wildcard: z.boolean(),
          rdata_len_bytes: z.number().int().nonnegative(),
          txt: z.string(),
        }),
      },
      async ({ input }) => {
        const result = validateForSaleTXT(input as any);
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
      }
    );

    // 5) One-shot: resolve + validate (explicit tool)
    this.server.tool(
      "resolve_and_validate_for_sale",
      {
        domain: z.string(),
        method: z.enum(["doh", "resolver"]).default("doh"),
      },
      async ({ domain, method }) => {
        if (!isDomain(domain)) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: "Invalid domain" }) }],
          };
        }
        const res = await resolveAndValidate(domain, method);
        // If no versioned record present, return a spec-compliant invalid result for visibility.
        if (!res.records.length) {
          const empty = {
            valid: false,
            errors: ["no _for-sale TXT record found"],
            record_info: {
              query_fqdn: `${res.queried_name}.`,
              final_fqdn: `${res.queried_name}.`,
              cross_zone: false,
              is_wildcard: false,
              alias_chain: [],
            },
            parsed: null,
            explanations: {
              summary: "Invalid: no versioned _for-sale TXT found.",
              rule_evaluations: [
                {
                  rule: "presence of versioned record",
                  status: "fail",
                  why: "No TXT starting with v=FORSALE1; present.",
                },
              ],
            },
          };
          return { content: [{ type: "text", text: JSON.stringify({ ...res, validations: [empty] }) }] };
        }
        return { content: [{ type: "text", text: JSON.stringify(res) }] };
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

