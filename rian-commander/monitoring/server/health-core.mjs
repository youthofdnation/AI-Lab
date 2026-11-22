/**
 * Health & Inspection core: tenant directory, per-tenant keys, sample validation, thresholds.
 * Separate from the remote-execution V2 directory: principals here are `owner` (read) and
 * `collector` (ingest for exactly one device). No principal kind can request a device action.
 */
import {createHash,createHmac,createCipheriv,createDecipheriv,randomBytes,timingSafeEqual,hkdfSync} from 'node:crypto';

export const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
export const NAME=/^[A-Za-z0-9][A-Za-z0-9 ._@:+()-]{0,99}$/;
export const INTERVAL_SECONDS=300;
export const DEFAULT_THRESHOLDS=Object.freeze({cpuPercent:90,cpuMinutes:10,ramPercent:90,ramMinutes:10,diskPercent:85,serviceMisses:2,offlineMinutes:15});
const EMAIL=/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;

const requireId=(v,code='INVALID_ID')=>{if(typeof v!=='string'||!ID.test(v))throw Error(code);return v;};
const isSha=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);

function normalizeEmail(e){
  const cfg={enabled:false,recipients:[],from:null,smtp:null};
  if(e==null)return Object.freeze(cfg);
  if(typeof e!=='object')throw Error('INVALID_EMAIL_CONFIG');
  const recipients=Array.isArray(e.recipients)?e.recipients:[];
  if(recipients.length>10||!recipients.every(r=>typeof r==='string'&&EMAIL.test(r)))throw Error('INVALID_EMAIL_CONFIG');
  if(e.from!=null&&(typeof e.from!=='string'||!EMAIL.test(e.from)))throw Error('INVALID_EMAIL_CONFIG');
  let smtp=null;
  if(e.smtp!=null){
    const s=e.smtp;
    if(typeof s.host!=='string'||!/^[A-Za-z0-9.-]{1,253}$/.test(s.host)||!Number.isInteger(s.port)||s.port<1||s.port>65535)throw Error('INVALID_EMAIL_CONFIG');
    if(s.user!=null&&typeof s.user!=='string')throw Error('INVALID_EMAIL_CONFIG');
    if(s.passwordEnv!=null&&!/^[A-Z][A-Z0-9_]{2,63}$/.test(s.passwordEnv))throw Error('INVALID_EMAIL_CONFIG');
    smtp=Object.freeze({host:s.host,port:s.port,implicitTls:s.implicitTls!==false,user:s.user||null,passwordEnv:s.passwordEnv||null,allowLoopbackPlain:s.allowLoopbackPlain===true});
  }
  // Sending needs all three: explicit enable, at least one recipient, a sender and transport.
  const enabled=e.enabled===true&&recipients.length>0&&!!e.from&&!!smtp;
  return Object.freeze({enabled,recipients:Object.freeze([...recipients]),from:e.from||null,smtp});
}

export class HealthDirectory{
  #tenants=new Map();#devices=new Map();#principals=[];
  constructor({tenants,devices,principals}){
    if(!Array.isArray(tenants)||!Array.isArray(devices)||!Array.isArray(principals)||!tenants.length)throw Error('INVALID_DIRECTORY');
    for(const t of tenants){
      const id=requireId(t?.id);
      if(this.#tenants.has(id))throw Error('DUPLICATE_TENANT');
      const thresholds={...DEFAULT_THRESHOLDS,...(t.thresholds||{})};
      for(const [k,v] of Object.entries(thresholds))if(!(k in DEFAULT_THRESHOLDS)||!Number.isFinite(v)||v<=0||v>10000)throw Error('INVALID_THRESHOLDS');
      this.#tenants.set(id,Object.freeze({id,name:typeof t.name==='string'&&t.name.trim()?t.name.trim().slice(0,60):id,thresholds:Object.freeze(thresholds),email:normalizeEmail(t.email)}));
    }
    for(const d of devices){
      const id=requireId(d?.id),tenantId=requireId(d?.tenantId);
      if(!this.#tenants.has(tenantId))throw Error('UNKNOWN_TENANT');
      if(this.#devices.has(id))throw Error('DUPLICATE_DEVICE');
      this.#devices.set(id,Object.freeze({id,tenantId,label:typeof d.label==='string'?d.label.slice(0,60):id}));
    }
    const names=new Set(),hashes=new Set();
    for(const p of principals){
      const id=requireId(p?.id),tenantId=requireId(p?.tenantId);
      if(!this.#tenants.has(tenantId)||!['owner','collector'].includes(p.kind)||!isSha(p.tokenSha256))throw Error('INVALID_PRINCIPAL');
      if(names.has(id)||hashes.has(p.tokenSha256))throw Error('DUPLICATE_PRINCIPAL');
      let deviceId=null;
      if(p.kind==='collector'){deviceId=requireId(p.deviceId);if(this.#devices.get(deviceId)?.tenantId!==tenantId)throw Error('INVALID_PRINCIPAL_DEVICE');}
      else if(p.deviceId!=null)throw Error('INVALID_PRINCIPAL_DEVICE');
      names.add(id);hashes.add(p.tokenSha256);
      this.#principals.push({hash:Buffer.from(p.tokenSha256,'hex'),actor:Object.freeze({id,tenantId,kind:p.kind,deviceId})});
    }
  }
  authenticate(header){
    if(typeof header!=='string'||!header.startsWith('Bearer '))throw Error('UNAUTHENTICATED');
    const token=header.slice(7);
    if(!/^[A-Za-z0-9_-]{40,256}$/.test(token))throw Error('UNAUTHENTICATED');
    const h=createHash('sha256').update(token).digest();
    let found=null;
    for(const p of this.#principals)if(timingSafeEqual(h,p.hash))found=p.actor; // full scan: no early exit timing
    if(!found)throw Error('UNAUTHENTICATED');
    return found;
  }
  tenant(id){const t=this.#tenants.get(id);if(!t)throw Error('NOT_FOUND');return t;}
  tenants(){return [...this.#tenants.values()];}
  devicesOf(tenantId){return [...this.#devices.values()].filter(d=>d.tenantId===tenantId);}
  allDevices(){return [...this.#devices.values()];}
  /** Owner view of a device: a device of another tenant is indistinguishable from a missing one. */
  ownedDevice(actor,deviceId){
    if(actor?.kind!=='owner')throw Error('NOT_FOUND');
    const d=this.#devices.get(deviceId);
    if(!d||d.tenantId!==actor.tenantId)throw Error('NOT_FOUND');
    return d;
  }
}

/** Per-tenant AES-256-GCM keys derived from one master key. */
export class TenantVault{
  #master;#cache=new Map();
  constructor(masterKeyHex){
    if(typeof masterKeyHex!=='string'||!/^[a-f0-9]{64}$/.test(masterKeyHex))throw Error('INVALID_MASTER_KEY');
    this.#master=Buffer.from(masterKeyHex,'hex');
  }
  #key(tenantId,purpose){
    const k=tenantId+'|'+purpose;
    if(!this.#cache.has(k))this.#cache.set(k,Buffer.from(hkdfSync('sha256',this.#master,'rian-health-v1','tenant|'+tenantId+'|'+purpose,32)));
    return this.#cache.get(k);
  }
  encrypt(tenantId,aad,plain){
    const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',this.#key(tenantId,'data'),iv);
    c.setAAD(Buffer.from(aad));
    const cipher=Buffer.concat([c.update(Buffer.isBuffer(plain)?plain:Buffer.from(plain)),c.final()]);
    return {cipher,iv,tag:c.getAuthTag()};
  }
  decrypt(tenantId,aad,{cipher,iv,tag}){
    const d=createDecipheriv('aes-256-gcm',this.#key(tenantId,'data'),Buffer.from(iv));
    d.setAAD(Buffer.from(aad));d.setAuthTag(Buffer.from(tag));
    return Buffer.concat([d.update(Buffer.from(cipher)),d.final()]);
  }
  /** Stable lookup id for a label (service name, mount) without storing the label in clear. */
  lookup(tenantId,text){return createHmac('sha256',this.#key(tenantId,'lookup')).update(text).digest('hex').slice(0,32);}
}

const num=(v,min,max)=>typeof v==='number'&&Number.isFinite(v)&&v>=min&&v<=max;
const bytes=v=>Number.isSafeInteger(v)&&v>=0;

/** Validates a collector sample. Unknown fields are dropped; nothing is executed or echoed. */
export function validateSample(body,actor,nowSeconds){
  if(!body||typeof body!=='object'||Array.isArray(body))throw Error('INVALID_SAMPLE');
  if(body.deviceId!==actor.deviceId)throw Error('DEVICE_MISMATCH');
  const ts=body.collectedAt;
  if(!Number.isSafeInteger(ts)||Math.abs(ts-nowSeconds)>600)throw Error('CLOCK_SKEW');
  const out={ts,os:null,cpu:null,memory:null,disks:[],services:[],collection:{ok:false,errors:[]}};
  const o=body.os;
  if(o&&typeof o==='object')out.os={family:['macOS','Linux','Windows'].includes(o.family)?o.family:'Other',version:String(o.version??'').slice(0,64),arch:String(o.arch??'').slice(0,32)};
  if(body.cpu!=null){if(!num(body.cpu.percent,0,100))throw Error('INVALID_SAMPLE');out.cpu={percent:Math.round(body.cpu.percent*10)/10};}
  if(body.memory!=null){
    const m=body.memory;
    if(!bytes(m.totalBytes)||!bytes(m.usedBytes)||m.usedBytes>m.totalBytes||!num(m.percent,0,100))throw Error('INVALID_SAMPLE');
    out.memory={totalBytes:m.totalBytes,usedBytes:m.usedBytes,percent:Math.round(m.percent*10)/10};
  }
  if(!Array.isArray(body.disks??[])||(body.disks??[]).length>16)throw Error('INVALID_SAMPLE');
  for(const d of body.disks??[]){
    if(typeof d?.mount!=='string'||!d.mount||d.mount.length>200||!bytes(d.totalBytes)||!bytes(d.usedBytes)||!bytes(d.freeBytes)||!num(d.percent,0,100))throw Error('INVALID_SAMPLE');
    out.disks.push({mount:d.mount,totalBytes:d.totalBytes,usedBytes:d.usedBytes,freeBytes:d.freeBytes,percent:Math.round(d.percent*10)/10});
  }
  if(!Array.isArray(body.services??[])||(body.services??[]).length>32)throw Error('INVALID_SAMPLE');
  for(const s of body.services??[]){
    if(typeof s?.name!=='string'||!NAME.test(s.name)||!['process','service'].includes(s.type)||![true,false,null].includes(s.running))throw Error('INVALID_SAMPLE');
    out.services.push({name:s.name,type:s.type,running:s.running});
  }
  const c=body.collection;
  if(c&&typeof c==='object'){
    out.collection.ok=c.ok===true;
    out.collection.errors=(Array.isArray(c.errors)?c.errors:[]).filter(x=>typeof x==='string'&&/^[A-Z][A-Z0-9_]{2,60}$/.test(x)).slice(0,16);
  }
  return out;
}

export const sha256Hex=t=>createHash('sha256').update(t).digest('hex');
export const newToken=()=>randomBytes(40).toString('base64url');
export const newId=()=>randomBytes(16).toString('hex');
