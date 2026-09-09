export const ISSUANCE_PURPOSE = "weave-issue-v1";
/** Nominal issuance record: only bytes produced by the issuance builder (or
 * validated through the issuance parser) inhabit this type, so a host or
 * consume record cannot be passed to the issuance verifier at compile time. */
export type IssuanceRecord = Uint8Array & { readonly __weaveRecordPurpose: "issuance" };
function assertBigIntMs(s: string) {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(s)) throw new Error("bad BigInt grammar");
  const bi = BigInt(s);
  if (bi < 0n || bi > 9007199254740991n) throw new Error("out of range");
  if (s.includes(".") || s.includes("-") || s.includes(" ")) throw new Error("bad");
}
function assertHostPublic(s: string) { if (!/^[0-9a-f]{64}$/.test(s)) throw new Error("bad hostPublic"); }
export function buildIssuanceRecord(fields: IssuanceFields): IssuanceRecord {
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.stableId)) throw new Error("bad stableId");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.community)) throw new Error("bad community");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.device)) throw new Error("bad device");
  assertBigIntMs(fields.issuedAt); assertHostPublic(fields.hostPublic);
  const parts: Uint8Array[] = [];
  const add = (tag: number, value: string) => {
    const v = Buffer.from(value, "utf8");
    if (v.length > 255) throw new Error("too long");
    parts.push(new Uint8Array([tag, v.length, ...v]));
  };
  add(0x01, ISSUANCE_PURPOSE);
  add(0x30, "1");
  add(0x31, "1");
  add(0x40, "ed25519");
  add(0x10, fields.stableId);
  add(0x11, fields.hostPublic);
  add(0x12, fields.community);
  add(0x13, fields.device);
  add(0x20, fields.issuedAt);
  const total = parts.reduce((n,p)=>n+p.length,0);
  if (total>1024) throw new Error("too large");
  const out = new Uint8Array(total);
  let o=0; for(const p of parts){out.set(p,o); o+=p.length;}
  return out as IssuanceRecord;
}
const ORDER = [0x01,0x30,0x31,0x40,0x10,0x11,0x12,0x13,0x20];
const ALLOWED = new Set(ORDER);
export type IssuanceFields = { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string };
export function parseIssuanceRecord(buf: Uint8Array): IssuanceFields {
  if (buf.length===0) throw new Error("empty");
  if (buf.length>1024) throw new Error("outer bound");
  let i=0; let lastIdx=-1; const seen=new Set<number>(); const vals=new Map<number,string>();
  while(i<buf.length){
    if(i+2>buf.length) throw new Error("truncated");
    const tag=buf[i], len=buf[i+1];
    if(!ALLOWED.has(tag)) throw new Error("unknown tag");
    if(seen.has(tag)) throw new Error("duplicate");
    const idx=ORDER.indexOf(tag);
    if(idx<=lastIdx) throw new Error("out-of-order");
    if(i+2+len>buf.length) throw new Error("invalid length");
    const v=Buffer.from(buf.slice(i+2,i+2+len)).toString("utf8");
    vals.set(tag,v); seen.add(tag); lastIdx=idx; i+=2+len;
  }
  if(i!==buf.length) throw new Error("trailing");
  if(seen.size!==ORDER.length) throw new Error("missing tags");
  // canonical tag values
  if(vals.get(0x01)!=="weave-issue-v1") throw new Error("bad purpose");
  if(vals.get(0x30)!=="1") throw new Error("bad protocol");
  if(vals.get(0x31)!=="1") throw new Error("bad scheme");
  if(vals.get(0x40)!=="ed25519") throw new Error("bad primitive");
  // grammar
  if(!/^[0-9a-f]{64}$/.test(vals.get(0x11)??"")) throw new Error("bad hostPublic");
  if(!/^(0|[1-9][0-9]{0,15})$/.test(vals.get(0x20)??"")) throw new Error("bad issuedAt");
  if(BigInt(vals.get(0x20)!)>9007199254740991n) throw new Error("out of range");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x10)??"")) throw new Error("bad stableId");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x12)??"")) throw new Error("bad community");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x13)??"")) throw new Error("bad device");
  return { stableId: vals.get(0x10)!, hostPublic: vals.get(0x11)!, community: vals.get(0x12)!, device: vals.get(0x13)!, issuedAt: vals.get(0x20)! };
}
