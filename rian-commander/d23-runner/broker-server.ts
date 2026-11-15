import { timingSafeEqual } from "node:crypto";
import { D23Broker, DEVICE, TASK } from "./broker";

const env=Bun.env, operator=env.RIAN_D23_OPERATOR_TOKEN||"",approver=env.RIAN_D23_APPROVER_TOKEN||"",runner=env.RIAN_D23_RUNNER_TOKEN||"";
const signing=env.RIAN_D23_TASK_KEY||"",dbPath=env.RIAN_D23_DB_PATH||"";
if([operator,approver,runner].some(x=>x.length<48)||new Set([operator,approver,runner,signing]).size!==4||signing.length<32||!dbPath.startsWith("/data/"))throw Error("D23 broker secrets or durable /data volume path missing");
const broker=new D23Broker(dbPath,signing);
function trusted(req:Request,key:string){
 const value=req.headers.get("authorization")||"";
 const expected="Bearer "+key;
 const a=Buffer.from(value),b=Buffer.from(expected);
 return a.length===b.length&&timingSafeEqual(a,b);
}
const respond=(x:unknown,status=200)=>Response.json(x,{status,headers:{"cache-control":"no-store"}});
async function json(req:Request){
 if(req.headers.get("content-type")?.split(";")[0]!=="application/json")throw Error("json_required");
 const raw=await req.text();if(Buffer.byteLength(raw)>4096)throw Error("too_large");
 const obj=JSON.parse(raw);
 if(!obj||typeof obj!=="object"||Array.isArray(obj))throw Error("invalid_object");
 return obj;
}
const port=Number(env.PORT||3000);
Bun.serve({hostname:"0.0.0.0",port,async fetch(req){
 const url=new URL(req.url),p=url.pathname,m=req.method;
 if(p==="/health"&&m==="GET")return respond({ok:true,service:"rian-d23-restricted-broker",readonly_fleet_unchanged:true});
 try{
  if(p==="/v1/d23/enrollment/invite"&&m==="POST"){
   if(!trusted(req,operator))return respond({error:"unauthorized"},401);
   const x=await json(req);
   if(Object.keys(x).join(",")!=="device"||x.device!==DEVICE)return respond({error:"scope_denied"},403);
   return respond(broker.issueEnrollment(x.device),201);
  }
  if(p==="/v1/d23/enrollment/claim"&&m==="POST"){
   const x=await json(req);
   if(Object.keys(x).sort().join(",")!=="code,device"||x.device!==DEVICE)return respond({error:"enrollment_denied"},403);
   broker.claimEnrollment(x.device,x.code);
   return respond({device:DEVICE,registered:true,runner_token:runner,task_key:signing},
     200);
  }
  if(p==="/v1/d23/requests"&&m==="POST"){
   if(!trusted(req,operator))return respond({error:"unauthorized"},401);
   const x=await json(req);
   if(Object.keys(x).sort().join(",")!=="device,task"||x.device!==DEVICE||x.task!==TASK)return respond({error:"scope_denied"},403);
   return respond(broker.request(x.device,x.task),201);
  }
  if(p==="/v1/d23/approve"&&m==="POST"){
   if(!trusted(req,approver))return respond({error:"unauthorized"},401);
   const x=await json(req);
   if(Object.keys(x).join(",")!=="job_id")return respond({error:"scope_denied"},403);
   return respond(broker.approve(x.job_id));
  }
  if(p==="/v1/d23/lease"&&m==="POST"){
   if(!trusted(req,runner))return respond({error:"unauthorized"},401);
   const x=await json(req);
   if(Object.keys(x).join(",")!=="device"||x.device!==DEVICE)return respond({error:"scope_denied"},403);
   return respond(broker.lease());
  }
  if(p==="/v1/d23/complete"&&m==="POST"){
   if(!trusted(req,runner))return respond({error:"unauthorized"},401);
   const x=await json(req);
   if(Object.keys(x).sort().join(",")!=="job_id,nonce,result_path")return respond({error:"scope_denied"},403);
   return respond(broker.complete(x.job_id,x.nonce,x.result_path));
  }
  if(/^\/v1\/d23\/jobs\/[A-Za-z0-9_-]{16,64}$/.test(p)&&m==="GET"){
   if(!trusted(req,operator))return respond({error:"unauthorized"},401);
   return respond(broker.inspect(p.split("/").at(-1)!));
  }
  return respond({error:"not_found"},404);
 }catch(err){const message=String((err as Error).message).slice(0,100);return respond({error:message},400)}
}});
