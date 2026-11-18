
const DEV_TASK_PROFILE="dev-task-scope-v1",DEV_TASK_MARKER="RIAN_DEV_SCOPE_V1";
const DEV_TASK_ROOT="Documents/RIAN-Commander-Dev",DEV_TASK_HOME="Documents",DEV_TASK_POLICY="v1|owner-approved-manifest|one-repo-one-pr|no-push-clean-reset-delete-deploy|2026-11-18";
const DEV_TASK_MAX_BYTES=11500;
const DEV_TASK_SETUP_SCRIPT="from pathlib import Path;import sys;r=Path('RIAN-Commander-Dev');assert not r.is_symlink();r.mkdir(exist_ok=True);assert r.resolve().parent==Path.cwd().resolve();p=r/sys.argv[1];assert not p.exists() and not p.is_symlink();p.mkdir();print('RIAN_DEV_READY')";
const DEV_TASK_GUARD_SCRIPT="from pathlib import Path;import sys;r=Path('RIAN-Commander-Dev');p=r/sys.argv[1];assert r.is_dir() and not r.is_symlink() and r.resolve().parent==Path.cwd().resolve() and p.is_dir() and not p.is_symlink() and p.resolve().parent==r.resolve();assert all(not (p/x).is_symlink() for x in ('repo','tree'));print('RIAN_DEV_GUARD_OK')";
const DEV_TASK_FILE_GUARD_SCRIPT="from pathlib import Path;import sys;r=Path('RIAN-Commander-Dev')/sys.argv[1]/'tree';p=r/sys.argv[2];assert r.is_dir() and not r.is_symlink() and p.parent.resolve().is_relative_to(r.resolve());assert not p.is_symlink() and all(not x.is_symlink() for x in p.parents if x.exists());print('RIAN_DEV_FILE_OK')";
export function devTaskSafePath(path,extension){
 if(typeof path!=="string"||path.length>180||path.startsWith("/")||path.includes("\\")||path.includes(":"))return false;
 const segments=path.split("/");
 if(segments.length>7||segments.length<2||segments.some(x=>!x||x==="."||x===".."||x.startsWith(".")||!/^[A-Za-z0-9_.-]+$/.test(x)))return false;
 if(segments.some(x=>["node_modules",".git",".github","secrets","credentials","dist","build","appdata"].includes(x.toLowerCase())))return false;
 const filename=segments.at(-1);
 if(filename.startsWith("test_")&&extension==="edit")return false;
 if(extension==="test")return path.startsWith("tests/")&&(/(^|\/)test_[a-zA-Z0-9_-]+\.py$/.test(path)||/^[a-zA-Z0-9_/-]+\.test\.(?:js|ts)$/.test(path));
 return /\.(?:py|ts|tsx|js|jsx|md|json|yaml|yml)$/.test(filename)&&!path.startsWith("tests/");
}
export function devTaskParseScope(raw){
 if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k))||raw.cwd!==DEV_TASK_HOME||!Array.isArray(raw.argv)||raw.argv.length!==8)throw Error("Development scope request shape denied");
 const [marker,owner,repo,pr,sha,test,testBlob,edits]=raw.argv;
 if(marker!==DEV_TASK_MARKER||typeof owner!=="string"||typeof repo!=="string"||!(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(owner))||!(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,65}$/.test(repo))||
    typeof pr!=="string"||!(/^[1-9][0-9]{0,5}$/.test(pr))||typeof sha!=="string"||!(/^[0-9a-f]{40}$/.test(sha))||
    typeof testBlob!=="string"||!(/^[0-9a-f]{40}$/.test(testBlob))||!devTaskSafePath(test,"test")||typeof edits!=="string")throw Error("Invalid repository, PR identity, test or hash");
 const editable=edits.split(";");
 if(editable.length<1||editable.length>4||new Set(editable).size!==editable.length||editable.includes(test)||!editable.every(x=>devTaskSafePath(x,"edit")))throw Error("Invalid exact-file edit scope");
 const id=(owner+"-"+repo+"-pr"+pr).toLowerCase();
 if(id.length>100||!/^[a-z0-9][a-z0-9_.-]+$/.test(id))throw Error("Workspace label denied");
 const timeout=raw.timeout===undefined?15:raw.timeout;
 if(!Number.isInteger(timeout)||timeout<1||timeout>30)throw Error("Scope request timeout denied");
 const url="https://github.com/"+owner+"/"+repo+".git";
 const base=DEV_TASK_ROOT+"/"+id,tree=base+"/tree";
 return {owner,repo,pr,sha,test,testBlob,editable,id,url,base,tree};
}
export function devTaskCommands(s){
 const shared=s.base,testArg=s.test;
 const testCmd=testArg.endsWith(".py")?
  ["python","-I","-c","import os;os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1';import pytest;raise SystemExit(pytest.main(['"+testArg+"','-q','-p','no:cacheprovider']))"]:
  ["bun","test",testArg];
 return [
  {name:"prepare",cwd:DEV_TASK_HOME,argv:["python","-I","-S","-c",DEV_TASK_SETUP_SCRIPT,s.id],limit:30},
  {name:"clone",cwd:shared,argv:["git","-c","credential.interactive=never","-c","core.hooksPath=NUL","clone","--no-checkout","--filter=blob:none",s.url,"repo"],limit:90},
  {name:"fetch",cwd:shared,argv:["git","-c","credential.interactive=never","-C","repo","fetch","--no-tags","origin","refs/pull/"+s.pr+"/head:refs/remotes/origin/pr-"+s.pr],limit:90},
  {name:"worktree",cwd:shared,argv:["git","-c","core.hooksPath=NUL","-c","filter.lfs.required=false","-c","filter.lfs.smudge=","-C","repo","worktree","add","--detach","../tree",s.sha],limit:90},
  {name:"status",cwd:shared,argv:["git","-C","tree","status","--short","--untracked-files=normal"],limit:30},
  {name:"head",cwd:shared,argv:["git","-C","tree","rev-parse","HEAD"],limit:30},
  {name:"worktrees",cwd:shared,argv:["git","-C","repo","worktree","list","--porcelain"],limit:30},
  {name:"diff",cwd:shared,argv:["git","-C","tree","diff","--",...s.editable],limit:30},
  {name:"tests",cwd:s.tree,argv:testCmd,limit:90},
 ];
}
export function devTaskAllowedCommand(raw,scope){
 if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k))||!Array.isArray(raw.argv))throw Error("Unexpected developer task arguments");
 const match=devTaskCommands(scope).find(x=>x.cwd===raw.cwd&&x.argv.length===raw.argv.length&&x.argv.every((v,i)=>v===raw.argv[i]));
 if(!match)throw Error("Command is outside approved project: no push, reset, clean, delete or general shell");
 const timeout=raw.timeout===undefined?match.limit:raw.timeout;
 if(!Number.isInteger(timeout)||timeout<1||timeout>match.limit)throw Error("Task command timeout exceeds approved maximum");
 return {argv:[...match.argv],cwd:match.cwd,timeout};
}
export function devTaskAllowedWrite(args,scope){
 if(!args||typeof args!=="object"||Array.isArray(args)||Object.keys(args).some(k=>!["path","content","overwrite"].includes(k))||typeof args.content!=="string"||!args.content.trim()||args.content.includes("\0")||
 Buffer.byteLength(args.content,"utf8")>DEV_TASK_MAX_BYTES||typeof args.overwrite!=="boolean")return false;
 const file=args.path?.startsWith(scope.tree+"/")?args.path.slice(scope.tree.length+1):null;
 return typeof file==="string"&&scope.editable.includes(file);
}
function devTaskScopeDigest(s){return projectDigest(DEV_TASK_POLICY+JSON.stringify(s)+DEV_TASK_GUARD_SCRIPT+DEV_TASK_FILE_GUARD_SCRIPT)}
async function devTaskCheckRun(argv,cwd,expect){
 const r=await relay("rian_eemf_run_command",{argv,cwd,timeout:25},true);
 if(r?.result?.exit_code!==0)throw Error("Developer task workspace or Git identity check failed");
 const stdout=String(r?.result?.stdout||"").trim();
 if(expect.startsWith("RIAN_")?!stdout.includes(expect):stdout!==expect)throw Error("Developer task remote identity mismatch");
}
async function devTaskPreflight(safe,scope){
 const cmd=devTaskCommands(scope).find(x=>safe.cwd===x.cwd&&JSON.stringify(safe.argv)===JSON.stringify(x.argv));
 if(!cmd)throw Error("Not approved task command");
 if(cmd.name==="prepare")return;
 await devTaskCheckRun(["python","-I","-S","-c",DEV_TASK_GUARD_SCRIPT,scope.id],DEV_TASK_HOME,"RIAN_DEV_GUARD_OK");
 if(cmd.name==="clone")return;
 await devTaskCheckRun(["git","-C","repo","remote","get-url","origin"],scope.base,scope.url);
 if(cmd.name==="fetch")return;
 if(cmd.name==="worktree"){
  await devTaskCheckRun(["git","-C","repo","rev-parse","refs/remotes/origin/pr-"+scope.pr],scope.base,scope.sha);
  return;
 }
 if(["status","head","diff","tests"].includes(cmd.name))
  await devTaskCheckRun(["git","-C","tree","rev-parse","HEAD"],scope.base,scope.sha);
 if(cmd.name==="tests")
  await devTaskCheckRun(["git","-C","tree","hash-object",scope.test],scope.base,scope.testBlob);
}
function devTaskMaySnapshot(clientId,path){
 for(const s of trustedSessions.values())
  if(s.profile===DEV_TASK_PROFILE&&s.clientId===clientId&&s.scope&&currentSessionState(s)==="ACTIVE"&&s.scope.editable.some(x=>path===s.scope.tree+"/"+x))return true;
 return false;
}
async function devTaskWrite(sid,args,clientId){
 const s=ownedSession(sid,clientId);
 if(s.profile!==DEV_TASK_PROFILE||currentSessionState(s)!=="ACTIVE"||s.remaining<=0||!s.scope||!devTaskAllowedWrite(args,s.scope))throw Error("Project edit not approved");
 if(s.busy)throw Error("Another task command is running");
 s.busy=true;
 try{
  if(s.sourceHash!==await trustedSourceDigest(DEV_TASK_PROFILE)||s.scopeHash!==devTaskScopeDigest(s.scope)){s.state="REVOKED";s.remaining=0;throw Error("Project grant policy changed")}
  const scope=s.scope,rel=args.path.slice(scope.tree.length+1);
  const statusCmd=devTaskCommands(scope).find(x=>x.name==="status");
  await devTaskPreflight({argv:statusCmd.argv,cwd:statusCmd.cwd},scope);
  await devTaskCheckRun(["python","-I","-S","-c",DEV_TASK_FILE_GUARD_SCRIPT,scope.id,rel],DEV_TASK_HOME,"RIAN_DEV_FILE_OK");
  const folder=args.path.slice(0,args.path.lastIndexOf("/")),basename=args.path.slice(args.path.lastIndexOf("/")+1);
  const listing=await relay("rian_eemf_list_directory",{path:folder});
  const found=listing?.result?.entries?.find(x=>x.name===basename);
  if(found&&found.type!=="file")throw Error("Target is not a plain file");
  if(Boolean(found)!==args.overwrite)throw Error("Create/overwrite mismatch");
  let before=null;
  if(args.overwrite){
   const snapshot=projectSnapshots.get(projectKey(clientId,args.path));
   if(!snapshot||snapshot.until<=now())throw Error("Read target source in chat before editing");
   const actual=await relay("rian_eemf_read_file",{path:args.path});
   before=actual?.result?.content;
   if(typeof before!=="string"||projectDigest(before)!==snapshot.hash)throw Error("Conflict: project source changed since last read");
   if(before===args.content)return sessionReply({device,profile:DEV_TASK_PROFILE,path:args.path,no_change:true,sha256:snapshot.hash,remaining_calls:s.remaining});
  }
  if(currentSessionState(s)!=="ACTIVE")throw Error("Approval expired before write");
  s.remaining--;auditTrusted("dev_task_write_started",sid,{path:rel,remaining:s.remaining});
  await relay("rian_eemf_write_file",{path:args.path,content:args.content,overwrite:args.overwrite},true);
  const result=await relay("rian_eemf_read_file",{path:args.path});
  if(result?.result?.content!==args.content)throw Error("Developer source write readback mismatch");
  projectTrackRead(clientId,args.path,args.content);
  auditTrusted("dev_task_write_verified",sid,{path:rel,remaining:s.remaining});
  return sessionReply({device,profile:DEV_TASK_PROFILE,path:args.path,write_verified:true,old_sha256:before?projectDigest(before):null,sha256:projectDigest(args.content),remaining_calls:s.remaining,diff:projectDiff(before||"",args.content)});
 }finally{s.busy=false}
}
