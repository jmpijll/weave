export const HOST_PURPOSE = "candidate:weave-host-v1";
export function buildHostPossessionRecord(fields: { stableId: string; hostPublic: string; issuedAt: string }): Uint8Array {
  const parts: Uint8Array[] = [];
  const add = (tag:number, v:string)=>{ const b=Buffer.from(v,"utf8"); parts.push(new Uint8Array([tag,b.length,...b])); };
  add(0x01,HOST_PURPOSE); add(0x30,"candidate:1"); add(0x31,"candidate:1"); add(0x40,"candidate:ed25519");
  add(0x10,fields.stableId); add(0x11,fields.hostPublic); add(0x20,fields.issuedAt);
  const total=parts.reduce((n,p)=>n+p.length,0); const out=new Uint8Array(total); let o=0; for(const p of parts){out.set(p,o); o+=p.length;} return out;
}
