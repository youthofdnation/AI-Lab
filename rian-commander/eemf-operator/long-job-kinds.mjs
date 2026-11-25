/**
 * RIAN Commander V2 long-running job kinds.
 *
 * The server never sends argv, a shell string, a working directory or a file
 * path to an agent. A job is only (kind, bounded params). Each agent keeps its
 * own local allowlist and builds the fixed local operation itself, so a
 * compromised relay cannot turn a mail sync into an arbitrary command.
 *
 * Mail bounds are NOT re-invented here: they come from the reviewed
 * `planOutlookOperation` scope (1-14 day sync, <=1000 messages, one hex message
 * ID per read, metadata-only search). No kind can send, delete or move mail.
 */
import {createHash} from 'node:crypto';
import {planOutlookOperation} from './outlook-ops-scope.mjs';

const sha=x=>createHash('sha256').update(x).digest('hex');
function exactKeys(params,allowed,required=allowed){
  if(!params||typeof params!=='object'||Array.isArray(params))throw Error('INVALID_PARAMS');
  if(Object.keys(params).some(k=>!allowed.includes(k))||required.some(k=>!Object.hasOwn(params,k)))throw Error('INVALID_PARAMS');
}
function plan(request){
  try{return planOutlookOperation(request);}catch(e){throw Error('MAIL_SCOPE_DENIED:'+String(e.message).slice(0,40));}
}

const MAIL_KINDS={
  'mail.sync':{
    label:'업무메일 색인 동기화 (신규 메일 병합, 기존 색인 자동 백업)',
    lockGroup:'mail-index',maxRuntimeSeconds:3600,leaseSeconds:120,grantable:true,
    validate(p){
      exactKeys(p,['days','maxMessages']);
      const planned=plan({kind:'sync',days:p.days,maxMessages:p.maxMessages});
      if(planned.mode!=='DURABLE_BACKGROUND_JOB_REQUIRED'||planned.maySend||planned.mayDelete||planned.mayWriteMailbox)throw Error('MAIL_SCOPE_DENIED');
      return {days:p.days,maxMessages:p.maxMessages};
    },
    describe:p=>['최근 '+p.days+'일, 최대 '+p.maxMessages+'건을 읽기 전용(IMAP EXAMINE / BODY.PEEK)으로 가져와 로컬 색인에 병합',
      '기존 색인은 쓰기 전에 자동 백업, 계정이 다르면 아무것도 바꾸지 않고 중단','메일 발송·삭제·이동·읽음 표시 변경 없음']
  },
  'mail.search':{
    label:'업무메일 메타데이터 검색 (제목·보낸사람·날짜만)',
    lockGroup:null,maxRuntimeSeconds:120,leaseSeconds:60,grantable:true,
    validate(p){
      exactKeys(p,['query','limit'],['query']);
      const limit=p.limit===undefined?20:p.limit;
      plan({kind:'search',query:p.query,limit});
      return {query:p.query,limit};
    },
    describe:p=>['검색어와 일치하는 메일의 제목·보낸사람·날짜·메시지 ID만 최대 '+p.limit+'건','본문은 반환하지 않음']
  },
  'mail.read':{
    label:'선택한 메일 1건 본문 읽기',
    lockGroup:null,maxRuntimeSeconds:120,leaseSeconds:60,grantable:false,
    validate(p){
      exactKeys(p,['messageId']);
      plan({kind:'read',messageId:p.messageId});
      return {messageId:p.messageId};
    },
    describe:p=>['메시지 ID '+p.messageId+' 단 1건의 본문만 (최대 64KB)','다른 메일·첨부파일·폴더는 열지 않음','본문은 서버 로그·감사 기록에 남기지 않음']
  }
};

const DIAG_KINDS={
  'diag.wait':{
    label:'합성 장시간 진단 작업 (대기·진행률 보고만, 파일·메일 접근 없음)',
    lockGroup:'diag',maxRuntimeSeconds:960,leaseSeconds:45,grantable:true,
    validate(p){
      exactKeys(p,['seconds']);
      if(!Number.isInteger(p.seconds)||p.seconds<1||p.seconds>900)throw Error('INVALID_PARAMS');
      return {seconds:p.seconds};
    },
    describe:p=>[p.seconds+'초 동안 대기하며 진행률만 보고','파일·메일·네트워크 접근 없음']
  }
};

const intIn=(v,lo,hi)=>{if(!Number.isInteger(v)||v<lo||v>hi)throw Error('INVALID_PARAMS');return v;};
/**
 * Fleet kinds (RIAN AI Fleet pool). Each agent builds the fixed local operation itself; none of
 * them takes a path, a command, a model name or a data file from the server. `gpu: true` kinds
 * share one 'gpu' lock group per PC and get a GPU memory hand-back check on completion.
 * `dataClass` is what the job touches: inventory/bench/probe only read the machine or make
 * synthetic tensors, so they are 'synthetic'.
 */
const FLEET_KINDS={
  'salpion.worker.status':{
    label:'Mac SALPION Nano AI 워커 상태 조회 (읽기 전용)',
    lockGroup:'salpion-worker',maxRuntimeSeconds:120,leaseSeconds:45,grantable:true,ramMiB:128,gpu:false,dataClass:'synthetic',
    validate(p){exactKeys(p,[]);return {};},
    describe:()=>['이 PC에 미리 등록된 Nano 워커의 프로세스 소유권, 로컬 상태, 모델 SHA-256 및 루프백 health만 조회',
      '토큰·영상·파일 내용·명령줄은 반환하지 않음']
  },
  'salpion.worker.start':{
    label:'Mac SALPION Nano AI 워커 시작 (고정된 로컬 구성, 매회 소유자 승인)',
    lockGroup:'salpion-worker',maxRuntimeSeconds:180,leaseSeconds:45,grantable:false,ramMiB:2048,gpu:false,dataClass:'synthetic',
    validate(p){exactKeys(p,[]);return {};},
    describe:()=>['이 PC의 소유자 구성에 고정된 Python·스크립트·Nano 가중치 SHA-256·개인 토큰 파일만 사용',
      '워커는 127.0.0.1에만 바인드, Tailscale/Serve·방화벽·ACL 변경 없음',
      '현재 메모리 압력 및 보호 서비스 확인 후 시작; 반복 승인 불가']
  },
  'salpion.worker.stop':{
    label:'Mac SALPION Nano AI 워커 종료 (소유 프로세스만, 매회 소유자 승인)',
    lockGroup:'salpion-worker',maxRuntimeSeconds:120,leaseSeconds:45,grantable:false,ramMiB:128,gpu:false,dataClass:'synthetic',
    validate(p){exactKeys(p,[]);return {};},
    describe:()=>['RIAN이 시작하고 PID·시작 시각·명령 정체성이 일치하는 Nano 워커 프로세스에만 종료 신호',
      'Youngmin 연구, LM Studio, Ollama, n8n, Docker 등 다른 프로세스는 건드리지 않음; 반복 승인 불가']
  },
  'fleet.inventory':{
    label:'장비 자원 읽기 (CPU·RAM·GPU·디스크·암호화·실행환경·AI 프로세스 이름, 읽기 전용)',
    lockGroup:'fleet-inventory',maxRuntimeSeconds:180,leaseSeconds:60,grantable:true,ramMiB:128,gpu:false,dataClass:'synthetic',
    validate(p){exactKeys(p,[]);return {};},
    describe:()=>['CPU·RAM·GPU·디스크 사용량, 디스크 암호화 상태, OS·CUDA·PyTorch 버전, AI 서버 프로세스 이름 및 Windows GPU 엔진의 PID·프로세스 이름·점유율 표본만 읽음',
      '프로세스 명령줄·파일 내용·인증정보는 읽지 않음, 아무것도 바꾸거나 종료하지 않음']
  },
  'fleet.cpu_bench':{
    label:'합성 CPU 작업 1조각 (SHA-256 연쇄 계산, 파일·네트워크 접근 없음)',
    lockGroup:null,maxRuntimeSeconds:900,leaseSeconds:45,grantable:true,ramMiB:64,gpu:false,dataClass:'synthetic',workUnits:p=>p.units,
    validate(p){exactKeys(p,['chunk','units']);return {chunk:intIn(p.chunk,0,9999),units:intIn(p.units,1,200)};},
    describe:p=>['조각 '+p.chunk+': SHA-256 연쇄 '+p.units+'단위 계산 후 결과 해시와 걸린 시간만 보고','파일·네트워크·GPU 접근 없음']
  },
  'fleet.blob_verify':{
    label:'모델·백업 저장소 무결성 검사 (파일 이름=SHA-256인 저장소를 PC 안에서 해시 대조, 내용 반출 없음)',
    lockGroup:null,maxRuntimeSeconds:3600,leaseSeconds:60,grantable:true,ramMiB:256,gpu:false,dataClass:'public',
    validate(p){
      exactKeys(p,['store','shard','shards']);
      if(typeof p.store!=='string'||!/^[a-z][a-z0-9-]{1,31}$/.test(p.store))throw Error('INVALID_PARAMS');
      const shards=intIn(p.shards,1,64),shard=intIn(p.shard,0,63);if(shard>=shards)throw Error('INVALID_PARAMS');
      return {store:p.store,shard,shards};
    },
    describe:p=>['이 PC 설정에 등록된 저장소 "'+p.store+'"의 '+(p.shard+1)+'/'+p.shards+' 조각만 읽어 SHA-256을 파일 이름과 대조',
      '저장소 위치는 PC가 자기 설정에서 정함(서버는 이름만 보냄), 결과는 개수·바이트·불일치 파일 이름뿐','아무것도 쓰거나 옮기지 않음']
  },
  'dev.test_shard':{
    label:'코드 테스트 1조각 실행 (PC 설정의 고정 명령, 지정 커밋의 깨끗한 체크아웃에서만)',
    lockGroup:null,maxRuntimeSeconds:1800,leaseSeconds:60,grantable:true,ramMiB:2048,gpu:false,dataClass:'public',
    validate(p){
      exactKeys(p,['suite','commit','shard','shards']);
      if(typeof p.suite!=='string'||!/^[a-z][a-z0-9-]{1,31}$/.test(p.suite))throw Error('INVALID_PARAMS');
      if(typeof p.commit!=='string'||!/^[0-9a-f]{40}$/.test(p.commit))throw Error('INVALID_PARAMS');
      const shards=intIn(p.shards,1,64),shard=intIn(p.shard,0,63);if(shard>=shards)throw Error('INVALID_PARAMS');
      return {suite:p.suite,commit:p.commit,shard,shards};
    },
    describe:p=>['테스트 묶음 "'+p.suite+'"의 '+(p.shard+1)+'/'+p.shards+' 조각을 커밋 '+p.commit.slice(0,12)+'에서 실행',
      '명령과 체크아웃 위치는 PC 자기 설정이 정함, 체크아웃이 그 커밋이 아니거나 변경된 파일이 있으면 실행하지 않음',
      '결과는 통과/실패와 마지막 출력 일부(2KB)만']
  },
  'fleet.gpu_probe':{
    label:'GPU 할당·반환 확인 (합성 텐서 할당 후 하위 프로세스 종료, 메모리 반환 측정)',
    lockGroup:'gpu',maxRuntimeSeconds:300,leaseSeconds:45,grantable:true,ramMiB:512,gpu:true,dataClass:'synthetic',
    validate(p){exactKeys(p,['mib']);return {mib:intIn(p.mib,16,2048)};},
    describe:p=>[p.mib+' MiB 합성 텐서를 하위 프로세스에서 할당·해제','하위 프로세스 종료 후 GPU 메모리가 작업 전 수준으로 돌아왔는지 측정',
      '보호 대상 GPU 프로세스(운영 서버 등)가 있으면 시작하지 않음']
  },
  'youngmin.qlora_probe':{
    label:'Youngmin QLoRA 학습 가능성 사전 시험 (무작위 가중치·합성 토큰, 비공개 데이터 없음)',
    lockGroup:'gpu',maxRuntimeSeconds:3600,leaseSeconds:60,grantable:false,ramMiB:6144,gpu:true,dataClass:'synthetic',
    validate(p){
      exactKeys(p,['seqLen','batch','steps','rank','gradCheckpointing']);
      if(typeof p.gradCheckpointing!=='boolean')throw Error('INVALID_PARAMS');
      return {seqLen:intIn(p.seqLen,64,2048),batch:intIn(p.batch,1,8),steps:intIn(p.steps,1,20),rank:intIn(p.rank,4,64),gradCheckpointing:p.gradCheckpointing};
    },
    describe:p=>['공개 Qwen3-8B 구조를 무작위 가중치로 4-bit 적재 (가중치 다운로드·비공개 데이터 없음)',
      '합성 토큰 seq '+p.seqLen+', batch '+p.batch+', LoRA r'+p.rank+', '+p.steps+'스텝, gradient checkpointing '+(p.gradCheckpointing?'켬':'끔'),
      '최대 VRAM·적재 시간·스텝 시간 측정, 끝나면 GPU 메모리 반환 확인','매번 소유자 승인 필요 (반복 승인 불가)']
  }
};
export const FLEET_KIND_NAMES=Object.freeze(Object.keys(FLEET_KINDS));

export class LongJobKinds {
  #kinds;
  constructor({allowDiagnostics=false,allowFleet=false}={}){
    this.#kinds=new Map(Object.entries({...MAIL_KINDS,...(allowDiagnostics===true?DIAG_KINDS:{}),...(allowFleet===true?FLEET_KINDS:{})}));
  }
  names(){return [...this.#kinds.keys()];}
  get(kind){
    const k=typeof kind==='string'?this.#kinds.get(kind):undefined;
    if(!k)throw Error('UNKNOWN_JOB_KIND');
    return k;
  }
  /** Returns the canonical (re-built, never caller-owned) params and their exact spec hash. */
  canonical(deviceId,kind,params){
    const k=this.get(kind);
    const safe=k.validate(params);
    const ordered=Object.fromEntries(Object.keys(safe).sort().map(x=>[x,safe[x]]));
    return {kind:k,params:ordered,specSha:sha(JSON.stringify(['rian-long-job-v1',deviceId,kind,ordered]))};
  }
}
