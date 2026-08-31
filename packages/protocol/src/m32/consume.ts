export const CONSUME_PURPOSE = "candidate:weave-consume-v1";
export function buildConsumeRecord(fields: { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string; consumeFreshness: string }): Uint8Array {
  const parts: Uint8Array[] = [];
  const add = (t:number,v:string)=>{const b=Buffer.from(v,"utf8"); parts.push(new Uint8Array([t,b.length,...b]));};
  add(0x01,CONSUME_PURPOSE); add(0x30,"candidate:1"); add(0x31,"candidate:1"); add(0x40,"candidate:ed25519");
  add(0x10,fields.stableId); add(0x11,fields.hostPublic); add(0x12,fields.community); add(0x13,fields.device); add(0x20,fields.issuedAt); add(0x21,fields.consumeFreshness);
  const total=parts.reduce((n,p)=>n+p.length,0); const out=new Uint8Array(total); let o=0; for(const p of parts){out.set(p,o); o+=p.length;} return out;
}
