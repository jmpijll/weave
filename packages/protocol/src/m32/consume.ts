export const CONSUME_PURPOSE = "weave-consume-v1";
/** Nominal consume record: see IssuanceRecord. */
export type ConsumeRecord = Uint8Array & { readonly __weaveRecordPurpose: "consume" };
const CONSUME_ORDER=[0x01,0x30,0x31,0x40,0x10,0x11,0x12,0x13,0x20,0x21] as const;
const CONSUME_ALLOWED=new Set(CONSUME_ORDER);
export type ConsumeFields = { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string; consumeFreshness: string };
export function parseConsumeRecord(buf: Uint8Array): ConsumeFields {
  if(buf.length===0) throw new Error("empty"); if(buf.length>1024) throw new Error("outer bound");
  let i=0,last=-1; const seen=new Set<number>(); const vals=new Map<number,string>();
  while(i<buf.length){ if(i+2>buf.length) throw new Error("truncated"); const t=buf[i],l=buf[i+1]; if(!(CONSUME_ALLOWED as Set<number>).has(t)) throw new Error("unknown"); if(seen.has(t)) throw new Error("duplicate"); const idx=(CONSUME_ORDER as readonly number[]).indexOf(t); if(idx<=last) throw new Error("order"); if(i+2+l>buf.length) throw new Error("len"); const v=Buffer.from(buf.slice(i+2,i+2+l)).toString("utf8"); vals.set(t,v); seen.add(t); last=idx; i+=2+l; }
  if(seen.size!==CONSUME_ORDER.length) throw new Error("missing");
  if(vals.get(0x01)!=="weave-consume-v1") throw new Error("bad purpose"); if(vals.get(0x30)!=="1") throw new Error("bad protocol"); if(vals.get(0x31)!=="1") throw new Error("bad scheme"); if(vals.get(0x40)!=="ed25519") throw new Error("bad primitive");
  if(!/^[0-9a-f]{64}$/.test(vals.get(0x11)??"")) throw new Error("bad hostPublic"); if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x10)??"")) throw new Error("bad stableId"); if(!/^(0|[1-9][0-9]{0,15})$/.test(vals.get(0x20)??"")) throw new Error("bad issuedAt"); if(BigInt(vals.get(0x20)!)>9007199254740991n) throw new Error("out of range");
  if(!/^(0|[1-9][0-9]{0,15})$/.test(vals.get(0x21)??"")) throw new Error("bad consumeFreshness"); if(BigInt(vals.get(0x21)!)>9007199254740991n) throw new Error("out of range");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x12)??"")) throw new Error("bad community");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(vals.get(0x13)??"")) throw new Error("bad device");
  return { stableId: vals.get(0x10)!, hostPublic: vals.get(0x11)!, community: vals.get(0x12)!, device: vals.get(0x13)!, issuedAt: vals.get(0x20)!, consumeFreshness: vals.get(0x21)! };
}
export function buildConsumeRecord(fields: ConsumeFields): ConsumeRecord {
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.stableId)) throw new Error("bad stableId");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.community)) throw new Error("bad community");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.device)) throw new Error("bad device");
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fields.stableId)) throw new Error("bad stableId");
  if(!/^[0-9a-f]{64}$/.test(fields.hostPublic)) throw new Error("bad hostPublic");
  if(!/^(0|[1-9][0-9]{0,15})$/.test(fields.issuedAt) || BigInt(fields.issuedAt)>9007199254740991n) throw new Error("bad issuedAt");
  if(!/^(0|[1-9][0-9]{0,15})$/.test(fields.consumeFreshness) || BigInt(fields.consumeFreshness)>9007199254740991n) throw new Error("bad consumeFreshness");
  const parts: Uint8Array[] = [];
  const add = (t:number,v:string)=>{const b=Buffer.from(v,"utf8"); if(b.length>255) throw new Error("too long"); parts.push(new Uint8Array([t,b.length,...b]));};
  add(0x01,CONSUME_PURPOSE); add(0x30,"1"); add(0x31,"1"); add(0x40,"ed25519");
  add(0x10,fields.stableId); add(0x11,fields.hostPublic); add(0x12,fields.community); add(0x13,fields.device); add(0x20,fields.issuedAt); add(0x21,fields.consumeFreshness);
  const total=parts.reduce((n,p)=>n+p.length,0); if(total>1024) throw new Error("too large"); const out=new Uint8Array(total); let o=0; for(const p of parts){out.set(p,o); o+=p.length;} return out as ConsumeRecord;
}
