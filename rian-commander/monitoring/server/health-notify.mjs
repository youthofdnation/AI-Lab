/**
 * Incident e-mail: composition, outbox, delivery. One channel (e-mail) in the MVP.
 * Nothing is sent unless the tenant explicitly enabled e-mail with recipients, sender and SMTP.
 * Messages state observations only and always say that the cause is not confirmed.
 */
import net from 'node:net';
import tls from 'node:tls';
import {randomBytes} from 'node:crypto';
import {INCIDENT_LABELS} from './health-alerts.mjs';

export const kst=ts=>new Date((ts+9*3600)*1000).toISOString().replace('T',' ').slice(0,16)+' KST';

export function composeIncidentEmail({tenant,deviceLabel,event,info,ts}){
  const kind=INCIDENT_LABELS[info.type]||info.type,phase=event==='OPENED'?'발생':'복구';
  const lines=[
    `RIAN Commander 장애 ${phase} 알림`,'',
    `고객: ${tenant.name}`,`장치: ${deviceLabel}`,`유형: ${kind}${info.label&&!['CPU','RAM','연결'].includes(info.label)?' ('+info.label+')':''}`,
    `${phase} 시각: ${kst(ts)}`,
    ...(info.since&&event==='OPENED'?[`조건 충족 시작: ${kst(info.since)}`]:[]),
    ...(event==='RESOLVED'&&info.since?[`발생 시각: ${kst(info.since)}`,`지속 시간: ${Math.max(0,Math.round((ts-info.since)/60))}분`]:[]),
    ...(info.value!=null&&info.type!=='OFFLINE'?[`관측 최고값: ${info.value}%`]:[]),
    '','원인: 확인되지 않음 (수집 데이터에 원인 근거 없음)',
    '이 알림은 수집된 관측값과 임계치만을 근거로 합니다.'];
  return {to:[...tenant.email.recipients],from:tenant.email.from,subject:`[RIAN Commander] ${phase}: ${kind} — ${deviceLabel}`,text:lines.join('\n')};
}

export class Notifier{
  #pending=false;
  constructor({directory,store,transportFor=defaultTransport,autoDeliver=true,maxAttempts=3,log=()=>{}}){
    this.directory=directory;this.store=store;this.transportFor=transportFor;this.autoDeliver=autoDeliver;this.maxAttempts=maxAttempts;this.log=log;
  }
  enqueue(tenantId,deviceId,incidentId,event,info,ts){
    const tenant=this.directory.tenant(tenantId);
    const device=this.directory.devicesOf(tenantId).find(d=>d.id===deviceId);
    const message=composeIncidentEmail({tenant,deviceLabel:device?.label||deviceId,event,info,ts});
    return this.store.addOutbox(tenantId,incidentId,event,message,tenant.email.enabled?'QUEUED':'NOT_SENT_DISABLED',ts);
  }
  deliverSoon(){
    if(!this.autoDeliver||this.#pending)return;
    this.#pending=true;
    setImmediate(()=>{this.#pending=false;this.deliver().catch(()=>this.log('RIAN_HEALTH_DELIVERY_ERROR'));});
  }
  async deliver(){
    const done={sent:0,failed:0};
    for(const tenant of this.directory.tenants()){
      if(!tenant.email.enabled)continue;
      for(const m of [...this.store.outbox(tenant.id,'QUEUED'),...this.store.outbox(tenant.id,'RETRY')]){
        try{
          await this.transportFor(tenant).send(m.message);
          this.store.setOutboxStatus(m.id,'SENT');done.sent++;
        }catch(e){
          // Bounded: never an endless retry loop; error code only in logs.
          this.store.setOutboxStatus(m.id,m.attempts+1>=this.maxAttempts?'GAVE_UP':'RETRY');done.failed++;
          this.log('RIAN_HEALTH_SMTP_FAILED '+String(e?.message||'ERROR').slice(0,40));
        }
      }
    }
    return done;
  }
}

function defaultTransport(tenant){
  const password=tenant.email.smtp.passwordEnv?process.env[tenant.email.smtp.passwordEnv]||'':'';
  return new SmtpTransport(tenant.email.smtp,password);
}

const b64Header=s=>'=?UTF-8?B?'+Buffer.from(s,'utf8').toString('base64')+'?=';
const wrap76=s=>s.replace(/.{1,76}/g,'$&\r\n');

export function buildMime({from,to,subject,text},now=new Date()){
  for(const a of [from,...to])if(/[\r\n<>,]/.test(a))throw Error('INVALID_ADDRESS');
  return ['From: <'+from+'>','To: '+to.map(a=>'<'+a+'>').join(', '),'Subject: '+b64Header(subject),'Date: '+now.toUTCString().replace('GMT','+0000'),
    'Message-ID: <'+randomBytes(12).toString('hex')+'@rian-health>','MIME-Version: 1.0','Content-Type: text/plain; charset=UTF-8','Content-Transfer-Encoding: base64','',
    wrap76(Buffer.from(text.replace(/\r?\n/g,'\r\n'),'utf8').toString('base64'))].join('\r\n');
}

/** Minimal SMTP client: implicit TLS (465) by default; plaintext only to loopback test servers. */
export class SmtpTransport{
  constructor(smtp,password=''){this.smtp=smtp;this.password=password;}
  async send(message){
    const {host,port,implicitTls,user,allowLoopbackPlain}=this.smtp;
    const loopback=['127.0.0.1','localhost','::1'].includes(host);
    if(!implicitTls&&!(allowLoopbackPlain&&loopback))throw Error('SMTP_TLS_REQUIRED');
    const socket=implicitTls?tls.connect({host,port,servername:host,rejectUnauthorized:!(loopback&&allowLoopbackPlain)}):net.connect({host,port});
    socket.setTimeout(20000,()=>socket.destroy(Error('SMTP_TIMEOUT')));
    const replies=[],waiters=[];let buf='';
    socket.on('data',d=>{buf+=d.toString('utf8');let i;while((i=buf.indexOf('\r\n'))>=0){const line=buf.slice(0,i);buf=buf.slice(i+2);
      if(/^\d{3} /.test(line)||/^\d{3}$/.test(line)){const code=Number(line.slice(0,3));(waiters.shift()||(r=>replies.push(r)))(code);}}});
    const failed=new Promise((_,rej)=>{socket.on('error',rej);socket.on('close',()=>rej(Error('SMTP_CLOSED')));});
    failed.catch(()=>{});
    const reply=()=>Promise.race([new Promise(r=>replies.length?r(replies.shift()):waiters.push(r)),failed]);
    const expect=async(codes,cmd)=>{if(cmd!=null)socket.write(cmd+'\r\n');const c=await reply();if(!codes.includes(c))throw Error('SMTP_'+c);return c;};
    try{
      await expect([220]);
      await expect([250],'EHLO rian-health');
      if(user)await expect([235],'AUTH PLAIN '+Buffer.from('\0'+user+'\0'+this.password).toString('base64'));
      await expect([250],'MAIL FROM:<'+message.from+'>');
      for(const r of message.to)await expect([250,251],'RCPT TO:<'+r+'>');
      await expect([354],'DATA');
      await expect([250],buildMime(message).split('\r\n').map(l=>l.startsWith('.')?'.'+l:l).join('\r\n')+'\r\n.');
      await expect([221],'QUIT').catch(()=>{});
    }finally{socket.destroy();}
  }
}
