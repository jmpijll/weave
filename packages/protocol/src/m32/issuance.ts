export const ISSUANCE_PURPOSE = "candidate:weave-issue-v1";
export function buildIssuanceRecord(fields: { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string }): Uint8Array {
  // candidate TLV: tags 0x01,0x30,0x31,0x40,0x10,0x11,0x12,0x13,0x20 — minimal: encode as tag+len+value
  const parts: Uint8Array[] = [];
  const add = (tag: number, value: string) => {
    const v = Buffer.from(value, "utf8");
    if (v.length > 255) throw new Error("too long");
    parts.push(new Uint8Array([tag, v.length, ...v]));
  };
  add(0x01, ISSUANCE_PURPOSE);
  add(0x30, "candidate:1");
  add(0x31, "candidate:1");
  add(0x40, "candidate:ed25519");
  add(0x10, fields.stableId);
  add(0x11, fields.hostPublic);
  add(0x12, fields.community);
  add(0x13, fields.device);
  add(0x20, fields.issuedAt);
  const total = parts.reduce((n,p)=>n+p.length,0);
  if (total>1024) throw new Error("too large");
  const out = new Uint8Array(total);
  let o=0; for(const p of parts){out.set(p,o); o+=p.length;}
  return out;
}
export function parseIssuanceRecord(buf: Uint8Array): Record<string,string> { return {}; }
