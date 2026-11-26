/* Browser-only permission center. Polling reads state; every grant needs a user click and WebAuthn. */
const base='/v2/permissions';
const notice=document.getElementById('notice');
const center=document.getElementById('center');
const webauthn=window.SimpleWebAuthnBrowser;
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const when=value=>value===null?'직접 철회 시까지':value?new Date(value*1000).toLocaleString('ko-KR'):'—';
const notify=(message,error=false)=>{if(notice){notice.textContent=message;notice.setAttribute('role',error?'alert':'status');}};
async function post(path,data){
  const response=await fetch(base+'/api/'+path,{method:'POST',credentials:'same-origin',
    headers:{'content-type':'application/json'},body:JSON.stringify(data)});
  const result=await response.json();
  if(!response.ok)throw Error(result.error||'REQUEST_FAILED');
  return result;
}
function available(){
  if(!webauthn?.browserSupportsWebAuthn?.()){notify('이 브라우저에서 패스키를 사용할 수 없습니다. Windows Chrome/Edge 또는 Mac Safari에서 이 고정 주소를 열어 주세요.',true);return false;}
  return true;
}
async function passkeyLogin(){
  if(!available())return;
  notify('패스키 확인을 시작합니다…');
  try{
    const options=await post('login/options',{});
    const response=await webauthn.startAuthentication({optionsJSON:options.optionsJSON});
    await post('login/verify',{challenge_id:options.challenge_id,response});
    location.replace(base);
  }catch(error){notify('패스키 로그인 실패: '+error.message,true);}
}
document.getElementById('passkey-login')?.addEventListener('click',passkeyLogin);

const durations=[['day','24시간'],['week','7일'],['month','30일'],['until_revoked','직접 철회 시까지']];
const durationSelect=(current)=>'<select name="duration">'+durations.map(([value,label])=>
  '<option value="'+value+'"'+(current===value?' selected':'')+'>'+label+'</option>').join('')+'</select>';
const featureChoices=(features,allowed)=>allowed.map(feature=>'<label class="inline"><input type="checkbox" name="features" value="'+esc(feature)+'"'+
  (features.includes(feature)?' checked':'')+'> '+esc(feature)+'</label>').join('');
function scopeFrom(form){
  const data=new FormData(form);
  return {features:data.getAll('features'),duration:data.get('duration'),
    maxSyncDays:Number(data.get('maxSyncDays')),maxSyncMessages:Number(data.get('maxSyncMessages'))};
}
function scopeForm(id,features,allowed,duration,maxDays,maxMessages,buttonLabel,kind){
  return '<form data-action="'+kind+'" data-id="'+esc(id)+'"><p>허용 기능</p>'+featureChoices(features,allowed)+
    '<label>유효기간 '+durationSelect(duration)+'</label>'+
    '<label>동기화 최대 일수 <input type="number" name="maxSyncDays" min="1" max="14" value="'+esc(maxDays)+'" required></label>'+
    '<label>동기화 최대 건수 <input type="number" name="maxSyncMessages" min="1" max="1000" value="'+esc(maxMessages)+'" required></label>'+
    '<button type="submit">'+esc(buttonLabel)+'</button></form>';
}
const allMail=['mail.status','mail.sync','mail.search','mail.recent','mail.review_pending','mail.read'];
function render(state){
  const pending=state.requests.filter(p=>p.state==='PENDING'||p.renewable);
  const completed=state.requests.filter(p=>p.state==='APPROVED');
  const expired=state.requests.filter(p=>p.state==='EXPIRED'&&!p.renewable);
  const accountFor=id=>state.requests.find(p=>p.request_id===id)?.account||'이 계정';
  center.innerHTML='<section><h2>소유자 보안</h2><p>'+esc(state.tenant)+' / '+esc(state.owner)+
    ' · 로그인 방식: '+esc(state.auth_method)+' · 세션 만료: '+esc(when(state.session_expires_at))+'</p><p>등록된 패스키: '+
    state.passkeys.length+'개</p>'+(state.auth_method==='password'||state.auth_method==='google'?'<button data-action="register">Windows Hello·Touch ID·모바일 패스키 등록</button>'+
      state.passkeys.map(k=>'<p>패스키 …'+esc(k.id_suffix)+' · '+esc(when(k.created_at))+
        ' <button data-action="revoke-passkey" data-id="'+esc(k.id)+'">패스키 철회</button></p>').join(''):'')+
    '<button data-action="logout">로그아웃</button></section>'+
    '<section><h2>승인 대기 <small>자동 갱신</small></h2>'+
    (pending.length?pending.map(p=>'<article><h3>'+esc(p.device)+' · '+esc(p.account)+'</h3><p>계정: '+esc(p.account_type)+
      ' · OAuth 연결 …'+esc(p.client_ref_suffix)+' · 상태: '+(p.state==='EXPIRED'?'원래 15분 경과, 같은 요청에서 승인 가능':'승인 대기')+
      ' · 최종 가능 시간: '+esc(when(p.renewable_until_at))+'</p>'+
      scopeForm(p.request_id,p.features,p.features,p.duration,p.max_days,p.max_messages,'패스키로 이 범위 승인','approve-policy')+'</article>').join(''):
      '<p>대기 중인 읽기 전용 정책이 없습니다. ChatGPT의 기존 MCP에서 최초 정책 요청을 준비하면 이곳에 자동 표시됩니다.</p>')+
    (state.pending_jobs.length?'<h3>작업별 승인 대기</h3>'+state.pending_jobs.map(j=>'<article><p>'+esc(j.device)+' · '+esc(j.label)+
      ' · '+esc(j.state)+'</p><ul>'+j.lines.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul><p><code>'+esc(JSON.stringify(j.params))+
      '</code></p><button data-action="approve-job" data-id="'+esc(j.job_id)+'">패스키로 이번 작업만 승인</button></article>').join(''):'')+
    '</section><section><h2>활성 권한</h2>'+(state.grants.length?state.grants.map(g=>{
      const p=state.requests.find(x=>x.request_id===g.grant_id);
      return '<article><h3>'+esc(g.device)+' · '+esc(g.account||accountFor(g.grant_id))+'</h3><p>'+esc(g.kind)+' · '+esc(g.state)+
        (p?' · OAuth 연결 …'+esc(p.client_ref_suffix):'')+
        ' · 만료: '+esc(when(g.expires_at))+' · 사용: '+esc(g.calls_used??0)+
        (g.runs_left===undefined?'':' · 남은 실행: '+esc(g.runs_left))+'</p><p>허용 기능: '+esc((g.features||[]).join(', ')||g.kind)+'</p>'+
        '<button data-action="revoke" data-id="'+esc(g.grant_id)+'">즉시 철회</button>'+
        (g.kind==='read.policy'&&p?scopeForm(g.grant_id,g.features,allMail,p.duration,p.max_days,p.max_messages,
          '변경 요청 만들기 (적용 전 패스키 재승인)','change-policy'):'')+'</article>';}).join(''):'<p>활성 권한이 없습니다.</p>')+
    '</section><section><h2>요청 상태와 실행 이력</h2><p>완료 요청 '+completed.length+'건 · 최종 만료 요청 '+expired.length+'건</p>'+
    '<ul>'+state.requests.filter(p=>p.state==='APPROVED'||(p.state==='EXPIRED'&&!p.renewable)).slice(0,20).map(p=>
      '<li>'+esc(p.device)+' · '+esc(p.account)+' · '+esc(p.state==='APPROVED'?(p.grant?.state||'APPROVED'):'EXPIRED')+
      ' · 요청 '+esc(p.request_id.slice(0,8))+'</li>').join('')+'</ul>'+
    '<div class="grid"><article><h3>최근 작업</h3><ul>'+state.jobs.map(j=>'<li>'+esc(j.device)+' · '+esc(j.kind)+' · '+esc(j.state)+
      ' · '+esc(when(j.created_at))+'</li>').join('')+'</ul></article><article><h3>승인·철회 감사 기록</h3><ul>'+state.audit.map(a=>
      '<li>'+esc(a.action)+' · '+esc(when(a.ts))+' · '+esc(a.object_id.slice(0,8))+'</li>').join('')+'</ul></article></div></section>';
}
let last='';
async function refresh(force=false){
  if(!center)return;
  try{
    const response=await fetch(base+'/api/state',{credentials:'same-origin',cache:'no-store'});
    if(response.status===401){location.replace(base);return;}
    if(!response.ok)throw Error('상태 조회 실패');
    const data=await response.json(),serialized=JSON.stringify(data);
    if(force||serialized!==last){
      if(!force&&document.activeElement?.closest('#center article'))return;
      last=serialized;render(data);
    }
  }catch(error){notify(error.message,true);}
}
async function enroll(){
  if(!available())return;
  notify('패스키 등록을 시작합니다. Windows Hello 또는 기기의 인증을 확인하세요.');
  const options=await post('register/options',{});
  const response=await webauthn.startRegistration({optionsJSON:options.optionsJSON});
  await post('register/verify',{challenge_id:options.challenge_id,response});
  notify('패스키 등록 완료. 다음 로그인과 승인에서 암호를 다시 입력하지 않아도 됩니다.');
  await refresh(true);
}
async function approvePolicy(form){
  if(!available())return;
  const request_id=form.dataset.id,scope=scopeFrom(form);
  notify('선택한 장치·계정·기능·기간에 대한 패스키 인증을 시작합니다.');
  const options=await post('approve/options',{request_id,scope});
  const response=await webauthn.startAuthentication({optionsJSON:options.optionsJSON});
  const result=await post('approve/verify',{challenge_id:options.challenge_id,response,kind:'approve_policy'});
  notify('정책 등록 완료 · '+result.state+' · grant_id '+result.grant_id+' · 만료 '+when(result.expires_at));
  await refresh(true);
}
async function approveJob(id){
  if(!available())return;
  notify('이 작업 하나에 대한 패스키 인증을 시작합니다.');
  const options=await post('approve/options',{job_id:id});
  const response=await webauthn.startAuthentication({optionsJSON:options.optionsJSON});
  const result=await post('approve/verify',{challenge_id:options.challenge_id,response,kind:'approve_job'});
  notify('작업 승인 완료 · '+result.state+' · 작업 ID '+result.jobId);
  await refresh(true);
}
center?.addEventListener('submit',async event=>{
  const form=event.target.closest('form[data-action]');if(!form)return;
  event.preventDefault();
  const button=form.querySelector('button[type=submit]');if(button)button.disabled=true;
  try{
    if(form.dataset.action==='approve-policy')await approvePolicy(form);
    else if(form.dataset.action==='change-policy'){
      const result=await post('change',{grant_id:form.dataset.id,scope:scopeFrom(form)});
      notify('변경 요청이 생성됐습니다. 새 범위는 패스키로 승인할 때까지 적용되지 않습니다. 요청 ID '+result.request_id);
      await refresh(true);
    }
  }catch(error){notify('요청 실패: '+error.message,true);}
  finally{if(button?.isConnected)button.disabled=false;}
});
center?.addEventListener('click',async event=>{
  const button=event.target.closest('button[data-action]');if(!button)return;
  button.disabled=true;
  try{
    if(button.dataset.action==='register')await enroll();
    else if(button.dataset.action==='approve-job')await approveJob(button.dataset.id);
    else if(button.dataset.action==='revoke'){
      if(confirm('이 권한을 즉시 철회하시겠습니까?')){
        const result=await post('revoke',{grant_id:button.dataset.id});
        notify('권한 철회 완료 · '+result.grant_id);await refresh(true);
      }
    }else if(button.dataset.action==='revoke-passkey'){
      if(confirm('이 패스키를 즉시 철회하시겠습니까?')){
        await post('passkey/revoke',{id:button.dataset.id});notify('패스키 철회 완료');await refresh(true);
      }
    }else if(button.dataset.action==='logout'){
      await post('logout',{});location.replace(base);
    }
  }catch(error){notify('요청 실패: '+error.message,true);}
  finally{if(button.isConnected)button.disabled=false;}
});
if(center){refresh(true);setInterval(()=>refresh(),5000);}
