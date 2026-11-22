/**
 * One-page A4 PDF for the monthly report, without dependencies.
 * Latin text uses Helvetica; Korean uses the PDF standard CJK font HYGoThic-Medium
 * (Adobe-Korea1, UniKS-UCS2-H), which PDF viewers provide without embedding a font file.
 */
import {INCIDENT_LABELS} from './health-alerts.mjs';
import {kst} from './health-notify.mjs';

const W=595,H=842,M=40;
const esc=s=>s.replace(/[\\()]/g,'\\$&');
const hex16=s=>{let h='';for(const ch of s){const c=ch.codePointAt(0);h+=(c>0xffff?0x3f:c).toString(16).padStart(4,'0');}return h;};
const isAscii=c=>c>=0x20&&c<=0x7e;
const widthOf=(s,size)=>{let w=0;for(const ch of s){const c=ch.codePointAt(0);w+=isAscii(c)?(c===0x20?0.28:/[il.,:;|!'()\[\]]/.test(ch)?0.3:/[A-Z%@MW]/.test(ch)?0.68:0.55):1;}return w*size;};

function runs(s){
  const out=[];let cur='',ascii=null;
  for(const ch of s){const a=isAscii(ch.codePointAt(0));if(ascii!==null&&a!==ascii){out.push([ascii,cur]);cur='';}ascii=a;cur+=ch;}
  if(cur)out.push([ascii,cur]);
  return out;
}

function wrap(s,size,max){
  const lines=[];let line='';
  for(const word of s.split(/(\s+)/)){
    if(widthOf(line+word,size)<=max){line+=word;continue;}
    if(line.trim())lines.push(line.trimEnd());
    line=word.trimStart();
    while(widthOf(line,size)>max){let cut=line.length;while(cut>1&&widthOf(line.slice(0,cut),size)>max)cut--;lines.push(line.slice(0,cut));line=line.slice(cut);}
  }
  if(line.trim())lines.push(line.trimEnd());
  return lines;
}

class Page{
  constructor(){this.ops=[];this.y=H-M;this.truncated=false;}
  text(x,y,size,s,{bold=false,color=[0.1,0.12,0.16]}={}){
    // U+00B7 is mis-mapped by UniKS-UCS2-H (renders as another glyph): use an ASCII separator.
    s=s.replace(/^· /,'- ').replace(/·/g,'|');
    let op=`BT ${color.join(' ')} rg ${x.toFixed(1)} ${y.toFixed(1)} Td`;
    for(const [a,t] of runs(s))op+=a?` /${bold?'F1B':'F1'} ${size} Tf (${esc(t)}) Tj`:` /F2 ${size} Tf <${hex16(t)}> Tj`;
    this.ops.push(op+' ET');
  }
  rect(x,y,w,h,color){this.ops.push(`${color.join(' ')} rg ${x} ${y} ${w} ${h} re f`);}
  line(x1,y1,x2,y2){this.ops.push(`0.8 0.83 0.87 RG 0.5 w ${x1} ${y1} m ${x2} ${y2} l S`);}
  room(h){if(this.y-h<M+28){this.truncated=true;return false;}return true;}
  heading(s){if(!this.room(30))return false;this.y-=24;this.text(M,this.y,11.5,s,{bold:true,color:[0.08,0.24,0.5]});this.y-=5;this.line(M,this.y,W-M,this.y);this.y-=3;return true;}
  para(s,{size=9,indent=0,color}={}){
    for(const l of wrap(s,size,W-2*M-indent)){if(!this.room(size+4.5))return false;this.y-=size+4.5;this.text(M+indent,this.y,size,l,{color});}
    return true;
  }
}

export function renderReportPdf(report){
  const f=report.facts,p=new Page();
  // Header band
  p.rect(0,H-70,W,70,[0.07,0.13,0.22]);
  p.text(M,H-34,16,'RIAN Commander 월간 점검 보고서',{color:[1,1,1]});
  p.text(M,H-54,9,`${f.tenant.name} · 점검 기간 ${kst(f.period.from).slice(0,10)} ~ ${kst(f.period.to).slice(0,10)} · 작성 ${kst(f.generatedAt)}`,{color:[0.8,0.86,0.95]});
  p.y=H-78;
  if(f.synthetic){p.rect(M,p.y-16,W-2*M,16,[0.98,0.9,0.88]);p.text(M+6,p.y-11.5,8.5,'합성 데이터로 생성한 검증용 보고서입니다. 실제 운영 성과가 아닙니다.',{color:[0.7,0.1,0.1]});p.y-=18;}

  p.heading('1. 개요');
  p.para(`등록 장치 ${f.deviceCount}대 (수집 장치 ${f.reportingDevices}대) · 평균 수집 정상률 ${f.collectionRate??0}% · 장애 이벤트 ${f.incidents.length}건 (미복구 ${f.openIncidents}건)`);

  p.heading('2. 장치별 CPU · RAM · 디스크 현황');
  const cols=[[M,'장치'],[M+150,'수집률'],[M+205,'CPU 평균/p95/최대'],[M+315,'RAM 평균/최대'],[M+400,'디스크 최대'],[M+470,'장애']];
  if(p.room(14)){p.y-=13;p.rect(M,p.y-3,W-2*M,13,[0.93,0.95,0.97]);for(const [x,t] of cols)p.text(x+2,p.y,8,t,{color:[0.25,0.3,0.38]});}
  const rows=f.devices.slice(0,8);
  for(const d of rows){
    if(!p.room(12))break;p.y-=12;
    const disk=d.disks.length?Math.max(...d.disks.map(k=>k.max))+'%':'-';
    const n=f.incidents.filter(i=>i.device===d.device).length;
    const vals=[d.label.slice(0,26),d.samples?d.collectionRate+'%':'수신 없음',d.cpu?`${d.cpu.avg} / ${d.cpu.p95} / ${d.cpu.max}%`:'-',d.ram?`${d.ram.avg} / ${d.ram.max}%`:'-',disk,String(n)];
    cols.forEach(([x],i)=>p.text(x+2,p.y,8,vals[i]));
  }
  if(f.devices.length>rows.length)p.para(`외 ${f.devices.length-rows.length}대는 JSON 보고서 참조`,{size:7.5});

  p.heading('3. 장애 발생 · 복구 이력');
  if(!f.incidents.length)p.para('점검 기간 동안 관측된 장애 이벤트가 없습니다.');
  const shown=f.incidents.slice(0,9);
  for(const i of shown){
    const target=i.target&&!['CPU','RAM','연결'].includes(i.target)?` (${i.target})`:'';
    const end=i.resolvedAt?`복구 ${kst(i.resolvedAt).slice(5)} · ${i.durationMinutes}분`:'미복구';
    if(!p.para(`[${INCIDENT_LABELS[i.type]||i.type}] ${i.deviceLabel}${target} — 발생 ${kst(i.openedAt).slice(5)} → ${end}${i.peak!=null&&i.type!=='OFFLINE'?` · 최고 ${i.peak}%`:''} · 원인 미확인`,{size:8}))break;
  }
  if(f.incidents.length>shown.length)p.para(`외 ${f.incidents.length-shown.length}건은 JSON 보고서 참조`,{size:7.5});

  p.heading(report.summary.source==='ai'?'4. 운영 상태 요약 (AI 작성 · 사실 검증 통과)':'4. 운영 상태 요약 (규칙 기반)');
  for(const l of report.summary.lines.slice(0,6))if(!p.para('· '+l))break;

  p.heading('5. 조치 필요 항목');
  if(!report.actionItems.length)p.para('현재 조치가 필요한 항목이 없습니다.');
  for(const a of report.actionItems.slice(0,6))if(!p.para('· '+a))break;
  if(report.actionItems.length>6)p.para(`외 ${report.actionItems.length-6}건은 JSON 보고서 참조`,{size:7.5});

  p.heading('6. 데이터 미수집 및 확인되지 않은 사항');
  for(const u of report.unconfirmed.slice(0,6))if(!p.para('· '+u))break;
  if(report.unconfirmed.length>6)p.para(`외 ${report.unconfirmed.length-6}건은 JSON 보고서 참조`,{size:7.5});

  p.line(M,M+16,W-M,M+16);
  p.text(M,M+5,7,`관측값, 관측 시각, 확인 근거만 기재했으며 원인이 확인되지 않은 항목은 단정하지 않습니다.${p.truncated?' 지면 제한으로 일부 생략 — JSON 보고서 참조.':''}  1 / 1`,{color:[0.45,0.5,0.56]});
  return build(p.ops.join('\n'),`RIAN Commander 월간 점검 보고서 ${report.month}`);
}

function build(content,title){
  const objs=[
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 5 0 R /F1B 6 0 R /F2 7 0 R >> >> /Contents 4 0 R >>`,
    `<< /Length ${Buffer.byteLength(content,'latin1')} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
    '<< /Type /Font /Subtype /Type0 /BaseFont /HYGoThic-Medium /Encoding /UniKS-UCS2-H /DescendantFonts [8 0 R] >>',
    '<< /Type /Font /Subtype /CIDFontType0 /BaseFont /HYGoThic-Medium /CIDSystemInfo << /Registry (Adobe) /Ordering (Korea1) /Supplement 1 >> /FontDescriptor 9 0 R /DW 1000 >>',
    '<< /Type /FontDescriptor /FontName /HYGoThic-Medium /Flags 6 /FontBBox [-6 -145 1003 880] /ItalicAngle 0 /Ascent 880 /Descent -120 /CapHeight 880 /StemV 58 >>',
    `<< /Title <feff${hex16(title)}> /Producer (RIAN Commander Health) >>`];
  let out='%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';const offsets=[];
  objs.forEach((o,i)=>{offsets.push(Buffer.byteLength(out,'latin1'));out+=`${i+1} 0 obj\n${o}\nendobj\n`;});
  const xref=Buffer.byteLength(out,'latin1');
  out+=`xref\n0 ${objs.length+1}\n0000000000 65535 f \n`+offsets.map(o=>String(o).padStart(10,'0')+' 00000 n \n').join('');
  out+=`trailer\n<< /Size ${objs.length+1} /Root 1 0 R /Info 10 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out,'latin1');
}
