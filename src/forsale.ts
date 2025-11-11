// src/forsale.ts
const FORSALE_PREFIX = "v=FORSALE1;";

// Normalise TXT: strip omringende quotes indien aanwezig
function normalizeTxtLines(lines: string[]): string[] {
  return lines
    .map(s => s.trim())
    .map(s => (s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s))
    .filter(Boolean);
}

function extractAfterVersion(record: string): string | null {
  if (!record.startsWith(FORSALE_PREFIX)) return null;
  return record.slice(FORSALE_PREFIX.length); // kan leeg zijn
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

export function structuredParse(versioned: string[]) {
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
      // alleen v=FORSALE1; zonder content
    } else {
      out.unknown_tags.push({ tag, value });
    }
  }
  return out;
}

export function isDomain(name: string): boolean {
  return /^[A-Za-z0-9.-]{1,253}$/.test(name) && name.includes(".");
}

export function extractDomainFromPrompt(prompt: string): string | null {
  const re = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi;
  const m = re.exec(prompt);
  if (!m) return null;
  let d = m[1].replace(/^_for-sale\./i, "");
  return isDomain(d) ? d : null;
}

// Query via Cloudflare DoH JSON (sneller & native in Workers)
export async function queryTxtDoH(domain: string): Promise<{ raw: any; txt: string[] }> {
  const qname = `_for-sale.${domain}`;
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(qname)}&type=TXT`;
  const resp = await fetch(url, { headers: { Accept: "application/dns-json" } });
  const json = await resp.json();
  // JSON shape: { Answer: [{ data: "\"v=...\"" }, ...] }
  const answers: string[] =
    json?.Answer?.map((a: any) => (typeof a?.data === "string" ? a.data : "")) ?? [];
  const txt = normalizeTxtLines(answers);
  return { raw: json, txt };
}

// Alternatief: jouw JSON resolver
export async function queryTxtResolver(domain: string): Promise<{ raw: any; txt: string[] }> {
  const qname = `_for-sale.${domain}`;
  const url = `https://resolver.j78workers.workers.dev/${qname}/TXT.json`;
  const resp = await fetch(url);
  const raw = await resp.json().catch(async () => await resp.text());
  let candidates: string[] = [];
  if (raw && typeof raw === "object") {
    if (Array.isArray(raw.Answer)) candidates.push(...raw.Answer.map((x: any) => String(x)));
    if (Array.isArray(raw.answers)) candidates.push(...raw.answers.map((x: any) => String(x)));
    if (Array.isArray(raw.records)) {
      for (const r of raw.records) if (r && r.data) candidates.push(String(r.data));
    }
  }
  const txt = candidates.length ? normalizeTxtLines(candidates) : normalizeTxtLines(String(raw).split("\n"));
  return { raw, txt };
}

export function verdict(txt: string[]) {
  const versioned = txt.filter(s => s.startsWith(FORSALE_PREFIX));
  return { is_for_sale: versioned.length > 0, versioned };
}

