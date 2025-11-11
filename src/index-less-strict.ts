import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

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

function parseTagValue(content: string): { tag: string | null; value: string } | null {
  // Draft alignment: "at most one tag=value" after the version prefix.
  if (content === "") return { tag: null, value: "" }; // version-only record is allowed
  const m = content.match(/^([a-z]{4})=(.*)$/);
  if (!m) return null; // malformed following content
  const tag = m[1];
  const value = m[2];
  // More than one tag is not allowed (we treat any additional ';' as a second tag separator)
  if (value.includes(";")) return null;
  return { tag, value };
}

function parseFvalDraft(v: string): { currency?: string; amount?: string } {
  // Draft: currency = 1*ALPHA (typically uppercase), amount integer with optional fractional part (no explicit upper bounds)
  const m = v.match(/^([A-Z]+)([0-9]+(?:\.[0-9]+)?)$/);
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
    if (tag === null) {
      // version-only: no tag/value to collect
      continue;
    }
    if (tag === "fcod") out.fcod.push(value);
    else if (tag === "ftxt") out.ftxt.push(value);
    else if (tag === "furi") out.furi.push(value);
    else if (tag === "fval") {
      out.fval.push(value);
      const { currency, amount } = parseFvalDraft(value);
      if (currency && amount) out.fval_parsed.push({ currency, amount });
    } else {
      // Draft: unknown tags MAY be ignored by processors (do not fail)
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

/* ---------------------- FOR-SALE TXT VALIDATOR (DRAFT) ---------------- */

type ValidatorInput = {
  query_fqdn: string;
  final_fqdn: string;
  alias_chain: string[];
  is_wildcard: boolean;
  rdata_len_bytes: number;
  txt: string;
};

type RuleEval = { rule: string; status: "pass" | "fail" | "not_applicable"; why: string };

// Recommended (non-mandatory) schemes per draft guidance.
const RECOMMENDED_SCHEMES = new Set(["http", "https", "mailto", "tel"]);

function trimOuterQuotesOnce(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}

function isSingleStringRdata(lenBytes: number, txt: string): boolean {
  // We rely on provided length and a quick heuristic against multi-string concatenations.
  return lenBytes <= MAX_TXT_LEN && !/\\"\s*\\"/.test(txt);
}

function tokenizeAfterPrefixDraft(s: string): { tag: string | null; value: string } | null {
  const rest = s.slice(FORSALE_PREFIX.length);
  if (rest === "") return { tag: null, value: "" };
  const m = rest.match(/^([a-z]{4})=(.*)$/);
  if (!m) return null;
  const value = m[2];
  if (value.includes(";")) return null; // more than one tag/value not allowed
  return { tag: m[1], value };
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

export function validateForSaleTXT_DRAFT(input: ValidatorInput) {
  const out = makeBaseOutput(input);
  const rules: RuleEval[] = out.explanations.rule_evaluations;

  const rawTxtOriginal = input.txt;
  const txt = trimOuterQuotesOnce(rawTxtOriginal).trim();

  // Rule: single-string ≤255 octets (DNS TXT character-string)
  const single = isSingleStringRdata(input.rdata_len_bytes, rawTxtOriginal);
  rules.push({
    rule: "single-string ≤255 octets",
    status: single ? "pass" : "fail",
    why: single
      ? `Length reported as ${input.rdata_len_bytes} bytes; single TXT character-string.`
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

  // Tokenize after prefix -> at most one tag=value
  let tag: string | null = null;
  let valueRaw: string | null = null;
  if (hasPrefix) {
    const tv = tokenizeAfterPrefixDraft(txt);
    if (tv) {
      tag = tv.tag;
      valueRaw = tv.value;
      const why =
        tag === null ? "Version-only record (no tag=value), allowed by draft." : `One '${tag}=' found after prefix.`;
      rules.push({ rule: "at most one tag", status: "pass", why });
    } else {
      rules.push({
        rule: "at most one tag",
        status: "fail",
        why: "Malformed content or multiple tags detected (extra ';' or no tag=value).",
      });
      out.errors.push("record must contain at most one tag=value (or none)");
    }
  } else {
    rules.push({ rule: "at most one tag", status: "not_applicable", why: "Prefix check failed." });
  }

  // Known tags (others are ignored per draft)
  const isKnownTag = tag ? ["fcod", "ftxt", "furi", "fval"].includes(tag) : false;
  rules.push({
    rule: "unknown tags processing",
    status: tag === null || isKnownTag ? "pass" : "pass",
    why:
      tag === null
        ? "No tag present."
        : isKnownTag
        ? "Tag is recognized."
        : "Unknown tag present; draft allows ignoring unrecognized tags.",
  });

  // Tag-specific validation (draft-aligned, minimal & non-strict)
  let valueNorm: string | null = null;
  let uriExtras: any = { scheme: null, host_unicode: null, host_punycode: null, path: null, query: null };
  let priceExtras: any = { currency: null, amount_decimal: null };

  if (isKnownTag && valueRaw !== null) {
    if (tag === "furi") {
      // Draft: value MUST contain exactly one URI. No strict scheme/absolute/length requirements.
      // We'll make a best-effort parse for reporting; failure to parse does NOT invalidate.
      try {
        const url = new URL(valueRaw);
        const scheme = url.protocol.replace(":", "");
        uriExtras = {
          scheme,
          host_unicode: url.hostname || null,
          host_punycode: null, // IDNA reporting not required by draft; omit
          path: url.pathname || "/",
          query: url.search ? url.search.slice(1) : null,
        };
        valueNorm = url.toString();
        rules.push({
          rule: "URI parse (best-effort)",
          status: "pass",
          why:
            RECOMMENDED_SCHEMES.has(scheme)
              ? `Parsed as absolute URI; scheme '${scheme}' is recommended.`
              : `Parsed as absolute URI; scheme '${scheme}' is accepted (not specifically recommended).`,
        });
      } catch {
        // Could be a relative or non-WHATWG-URL-conformant but still an RFC3986 URI; accept per draft.
        valueNorm = null;
        rules.push({
          rule: "URI parse (best-effort)",
          status: "pass",
          why: "Value accepted as a URI per draft; parsing not required for validity.",
        });
      }
    }

    if (tag === "fcod") {
      // Draft: registry-defined codes; processors MAY accept opaque tokens. No strict format here.
      valueNorm = null;
      rules.push({
        rule: "fcod processing",
        status: "pass",
        why: "Treated as opaque token per draft; no strict format enforced by validator.",
      });
    }

    if (tag === "ftxt") {
      // Draft: opaque text; overall TXT string already limited to ≤255 by DNS; no extra length rule here.
      valueNorm = null;
      rules.push({
        rule: "ftxt processing",
        status: "pass",
        why: "Opaque text accepted; no decoding or linkification; bounded by DNS TXT char-string size.",
      });
    }

    if (tag === "fval") {
      const parsed = parseFvalDraft(valueRaw);
      if (parsed.currency && parsed.amount) {
        priceExtras = { currency: parsed.currency, amount_decimal: parsed.amount };
        valueNorm = `${parsed.currency} ${parsed.amount}`;
        rules.push({
          rule: "fval pattern (draft)",
          status: "pass",
          why: "Matches draft pattern: currency = [A-Z]+, amount = integer with optional fractional part.",
        });
      } else {
        // Draft is permissive; malformed value does not negate the for-sale signal,
        // but it's appropriate to flag as an error for this record's tag validity.
        rules.push({
          rule: "fval pattern (draft)",
          status: "fail",
          why: "Does not match draft-friendly pattern [A-Z]+[0-9]+(.[0-9]+)?",
        });
        out.errors.push("fval value does not match expected draft pattern");
      }
    }
  } else if (tag && !isKnownTag) {
    // Unknown tag present and ignored: no tag-specific checks apply.
    rules.push({ rule: "tag-specific validation", status: "not_applicable", why: "Unknown tag ignored per draft." });
  } else {
    rules.push({ rule: "tag-specific validation", status: "not_applicable", why: "No tag present." });
  }

  // Aliases/wildcards assessment (informational)
  rules.push({
    rule: "aliases/wildcards cross-zone check",
    status: "pass",
    why: out.record_info.cross_zone
      ? "Final TXT appears under a different registrable domain (heuristic)."
      : "No cross-zone detected (heuristic).",
  });

  // Finalize validity per draft:
  // Presence of the version prefix indicates "for sale". Tag presence/recognition refines information but is not required.
  const hasStructuralErrors = out.errors.length > 0 && !hasPrefix ? true : false;

  // Valid when: prefix present AND single-string TXT AND (no multi-tag/malformed content)
  const structurallyValid =
    single && hasPrefix && (rules.find(r => r.rule === "at most one tag")?.status !== "fail");

  out.valid = structurallyValid && !hasStructuralErrors;

  if (out.valid) {
    // Populate parsed only if we have a recognized tag; otherwise leave null per draft permissiveness.
    if (isKnownTag && valueRaw !== null) {
      out.parsed = {
        tag,
        value_raw: valueRaw!,
        value_norm: valueNorm,
        extras: {
          uri: uriExtras,
          price: priceExtras,
        },
      };
    } else {
      out.parsed = null;
    }
    out.explanations.summary =
      tag === null
        ? "Record is valid per draft: correct version prefix with no tag (version-only), indicating for sale."
        : isKnownTag
        ? "Record is valid per draft: correct version prefix with a single recognized tag; value accepted per tag rules."
        : "Record is valid per draft: correct version prefix with an unrecognized tag, which is ignored.";
  } else {
    out.parsed = null;
    out.explanations.summary =
      out.errors.length
        ? `Invalid per draft: ${out.errors.join("; ")}.`
        : "Invalid per draft: one or more structural checks failed.";
  }

  return out;
}

/* -------- resolver + validator wiring (validation ALWAYS runs) -------- */

async function resolveAndValidate_DRAFT(domain: string, method: "doh" | "resolver") {
  const res = await runQuery(domain, method);

  // Validate every versioned record with draft-aligned validator
  const validations = res.records.map((rec) =>
    validateForSaleTXT_DRAFT({
      query_fqdn: `${res.queried_name}.`,
      final_fqdn: `${res.queried_name}.`, // If alias chasing is added, update this and alias_chain.
      alias_chain: [],
      is_wildcard: false,
      rdata_len_bytes: rec.length, // best-effort proxy when actual byte length is unknown
      txt: rec,
    })
  );

  return { ...res, validations };
}

/* ----------------------------- MCP server ---------------------------- */

export class MyMCP extends McpAgent {
  server = new McpServer({
    name: "ForSale Checker",
    version: "2.0.0-draft-aligned",
  });

  async init() {
    // 1) Presence + ALWAYS validate (draft-aligned)
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
        const res = await resolveAndValidate_DRAFT(domain, method);
        return {
          content: [{ type: "text", text: JSON.stringify(res) }],
        };
      }
    );

    // 2) Structured extraction + ALWAYS validate (draft-aligned)
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
        const res = await resolveAndValidate_DRAFT(domain, method);
        return {
          content: [{ type: "text", text: JSON.stringify(res) }],
        };
      }
    );

    // 3) Natural language interface + ALWAYS validate (draft-aligned)
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
        const res = await resolveAndValidate_DRAFT(domain, method);
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

    // 4) Low-level validator (direct call with a single TXT record, draft-aligned)
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
        const result = validateForSaleTXT_DRAFT(input as any);
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
      }
    );

    // 5) One-shot: resolve + validate (explicit tool, draft-aligned)
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
        const res = await resolveAndValidate_DRAFT(domain, method);
        if (!res.records.length) {
          const empty = {
            valid: true, // Draft: presence of versioned record is the signal; here there is none, so we return a "no record" info object instead of invalidating format.
            errors: [],
            record_info: {
              query_fqdn: `${res.queried_name}.`,
              final_fqdn: `${res.queried_name}.`,
              cross_zone: false,
              is_wildcard: false,
              alias_chain: [],
            },
            parsed: null,
            explanations: {
              summary: "No v=FORSALE1; _for-sale TXT record found for this domain.",
              rule_evaluations: [
                {
                  rule: "presence of versioned record",
                  status: "fail",
                  why: "No TXT starting with v=FORSALE1; present in the RRset.",
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

