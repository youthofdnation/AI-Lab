/**
 * TEST-ONLY: runs the unmodified OAuth Owner Gateway (gateway.ts) under Node by
 * providing the two Bun APIs it uses (Bun.env, Bun.serve) on 127.0.0.1.
 * Lets the E2E drive the real OAuth register -> authorize -> token -> /mcp flow.
 */
import {createServer} from 'node:http';

if(process.env.RIAN_V2_E2E!=='1')throw Error('E2E_ONLY');
globalThis.Bun={
  env:process.env,
  serve({port,fetch}){
    const server=createServer(async(req,res)=>{
      try{
        const chunks=[];for await(const c of req)chunks.push(c);
        const headers=new Headers();
        for(const [k,v] of Object.entries(req.headers))if(typeof v==='string')headers.set(k,v);
        const body=Buffer.concat(chunks);
        const response=await fetch(new Request('http://127.0.0.1:'+port+req.url,{method:req.method,headers,...(body.length?{body}:{})}));
        res.writeHead(response.status,Object.fromEntries(response.headers.entries()));
        res.end(Buffer.from(await response.arrayBuffer()));
      }catch{if(!res.headersSent){res.writeHead(500);res.end();}}
    });
    server.listen(Number(port),'127.0.0.1',()=>console.log('RIAN_V2_E2E_GATEWAY_READY',port));
    return server;
  }
};
await import('./gateway.ts');
