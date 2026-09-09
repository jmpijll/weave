export const HOST_PURPOSE = "weave-host-v1";
/** Nominal host-possession record: see IssuanceRecord. */
export type HostPossessionRecord = Uint8Array & { readonly __weaveRecordPurpose: "host-possession" };
const UTF8_ENC = new TextEncoder();
const UTF8_DEC = new TextDecoder("utf-8", { fatal: true });
const HOST_ORDER=[0x01,0x30,0x31,0x40,0x10,0x11,0x20] as const;
const HOST_ALLOWED=new Set(HOST_ORDER);
export type HostFields = { stableId: string; hostPublic: string; issuedAt: string };
export function parseHostPossessionRecord(buf: Uint8Array): HostFields {
  if(buf.length===0) throw new Error("empty"); if(buf.length>1024) throw new Error("outer bound");
  let i=0,last=-1; const seen=new Set<number>(); const vals=new Map<number,string>();
  while(i<buf.length){ if(i+2>buf.length) throw new Error("truncated"); const t=buf[i],l=buf[i+1]; if(!(HOST_ALLOWED as Set<number>).has(t)) throw new Error("unknown"); if(seen.has(t)) throw new Error("duplicate"); const idx=(HOST_ORDER as readonly number[]).indexOf(t); if(idx<=last) throw new Error("order"); if(i+2+l>buf.length) throw new Error("len"); const v=UTF8_DEC.decode(buf.slice(i+2,i+2+l)); vals.set(t,v); seen.add(t); last=idx; i+=2+l; }
  if(seen.size!==HOST_ORDER.length) throw new Error("missing");
  if(vals.get(0x01)!=="weave-host-v1") throw new Error("bad purpose"); if(vals.get(0x30)!=="1") throw new Error("bad protocol"); if(vals.get(0x31)!=="1") throw new Error("bad scheme"); if(vals.get(0x40)!=="ed25519") throw new Error("bad primitive");
  if(!/^[0-9a-f]{64}$/.test(vals.get(0x11)??"")) throw new Error("bad hostPublic"); if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x10)??"")) throw new Error("bad stableId"); if(!/^(0|[1-9][0-9]{0,15})$/.test(vals.get(0x20)??"")) throw new Error("bad issuedAt"); if(BigInt(vals.get(0x20)!)>9007199254740991n) throw new Error("out of range");
  return { stableId: vals.get(0x10)!, hostPublic: vals.get(0x11)!, issuedAt: vals.get(0x20)! };
}
export function buildHostPossessionRecord(fields: HostFields): HostPossessionRecord {
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.stableId)) throw new Error("bad stableId");
  if(!/^[0-9a-f]{64}$/.test(fields.hostPublic)) throw new Error("bad hostPublic");
  if(!/^(0|[1-9][0-9]{0,15})$/.test(fields.issuedAt) || BigInt(fields.issuedAt)>9007199254740991n) throw new Error("bad issuedAt");
  const parts: Uint8Array[] = [];
  const add = (tag:number, v:string)=>{ const b=UTF8_ENC.encode(v); if(b.length>255) throw new Error("too long"); parts.push(new Uint8Array([tag,b.length,...b])); };
  add(0x01,HOST_PURPOSE); add(0x30,"1"); add(0x31,"1"); add(0x40,"ed25519");
  add(0x10,fields.stableId); add(0x11,fields.hostPublic); add(0x20,fields.issuedAt);
  const total=parts.reduce((n,p)=>n+p.length,0); if(total>1024) throw new Error("too large"); const out=new Uint8Array(total); let o=0; for(const p of parts){out.set(p,o); o+=p.length;} return out as HostPossessionRecord;
}
