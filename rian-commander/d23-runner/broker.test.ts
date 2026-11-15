import { test, expect } from "bun:test";
import { createHmac } from "node:crypto";
import { D23Broker, DEVICE, TASK } from "./broker";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const KEY="Z".repeat(48);
function broker(){return new D23Broker(":memory:",KEY)}
test("rejects weak signing key",()=>{expect(()=>new D23Broker(":memory:","short")).toThrow()});
test("rejects remote arbitrary command",()=>{const b=broker();expect(()=>b.request(DEVICE,"run_command",5000)).toThrow("scope_denied");b.close()});
test("rejects non-1Q destination",()=>{const b=broker();expect(()=>b.request("DESKTOP-EEMFO3L",TASK,5000)).toThrow("scope_denied");b.close()});
test("requires explicit separate approval",()=>{const b=broker();b.request(DEVICE,TASK,5000);expect(b.lease(5001)).toBeNull();b.close()});
test("signed manifest matches Python canonical HMAC contract",()=>{
 const b=broker();const j=b.request(DEVICE,TASK,5000);b.approve(j.job_id,5001);
 const lease=b.lease(5002)!;const v=lease.manifest.payload;
 const canon=JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a],[c])=>a.localeCompare(c))));
 const h=createHmac("sha256",KEY).update(canon).digest("hex");
 expect(lease.manifest.mac).toBe(h);
 expect(v.task).toBe(TASK);expect(v.device).toBe(DEVICE);expect(v.expires_at-v.issued_at).toBe(240);
 b.close();
});
test("same job cannot lease twice",()=>{const b=broker();const j=b.request(DEVICE,TASK,5000);b.approve(j.job_id,5000);expect(b.lease(5001)).not.toBeNull();expect(b.lease(5002)).toBeNull();b.close()});
test("approval expires",()=>{const b=broker();const j=b.request(DEVICE,TASK,5000);expect(()=>b.approve(j.job_id,5601)).toThrow("not_approvable");b.close()});
test("only leased nonce can complete",()=>{
 const b=broker(),j=b.request(DEVICE,TASK,5000);b.approve(j.job_id,5000);
 const lease=b.lease(5001)!;const path="status-20261115-171010-deadbeef.json";
 expect(()=>b.complete(j.job_id,"wrongnonceABCDEFGHIJ",path,5002)).toThrow("not_completable");
 expect(()=>b.complete(j.job_id,lease.manifest.payload.nonce,"../../evil",5002)).toThrow("invalid_completion");
 expect(b.complete(j.job_id,lease.manifest.payload.nonce,path,5002).state).toBe("COMPLETE");
 expect(()=>b.complete(j.job_id,lease.manifest.payload.nonce,path,5003)).toThrow();
 b.close();
});
test("durable sqlite state survives restart",()=>{
 const dir=mkdtempSync(join(tmpdir(),"rian-d23-broker-"));const path=join(dir,"jobs.db");
 try{const b=new D23Broker(path,KEY),j=b.request(DEVICE,TASK,5000);b.approve(j.job_id,5001);b.close();
 const again=new D23Broker(path,KEY);expect((again.inspect(j.job_id) as any).state).toBe("APPROVED");again.close();
 }finally{rmSync(dir,{recursive:true,force:true})}
});

test("stale approved job is expired, never leased",()=>{
 const b=broker();
 const j=b.request(DEVICE,TASK,5000);
 b.approve(j.job_id,5001);
 expect(b.lease(5702)).toBeNull();
 expect((b.inspect(j.job_id) as any).state).toBe("EXPIRED");
 b.close();
});
test("expired lease cannot be reissued or completed",()=>{
 const b=broker();
 const j=b.request(DEVICE,TASK,5000);
 b.approve(j.job_id,5000);
 const lease=b.lease(5001)!;
 expect(b.lease(5242)).toBeNull();
 expect((b.inspect(j.job_id) as any).state).toBe("EXPIRED");
 expect(()=>b.complete(j.job_id,lease.manifest.payload.nonce,"status-20261115-190000-deadbeef.json",5242)).toThrow("not_completable");
 b.close();
});
test("expired jobs free the capped queue",()=>{
 const b=broker();
 for(let i=0;i<3;i++) b.request(DEVICE,TASK,5000);
 expect(()=>b.request(DEVICE,TASK,5001)).toThrow("queue_full");
 expect(b.request(DEVICE,TASK,5700).state).toBe("PENDING_APPROVAL");
 b.close();
});
