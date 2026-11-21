// Lossless post-build size reduction for the Railway Function single-file Gateway.
// `bun build --minify` writes every Hangul syllable as a 6-byte \uXXXX escape.
// Inside JS string/template/regex literals the raw UTF-8 character (3 bytes) is
// the identical value, so this rewrites only odd-backslash 가-힣 escapes
// and proves the change is reversible byte-for-byte before saving.
import {readFileSync,writeFileSync} from "node:fs";

const file=process.argv[2];
if(!file)throw Error("usage: node compact-utf8.mjs <bundle.js>");
const source=readFileSync(file,"utf8");
if(/[가-힣]/.test(source))throw Error("Bundle already contains raw Hangul; refusing ambiguous rewrite");
if(/String\.raw`[^`]*\\u[A-F0-9]{4}/.test(source))throw Error("Escapes inside String.raw templates cannot be rewritten safely");
let replaced=0;
const compact=source.replace(/(\\+)u([0-9A-Fa-f]{4})/g,(match,slashes,hex)=>{
  const code=parseInt(hex,16);
  if(slashes.length%2===0||code<0xAC00||code>0xD7A3||hex!==hex.toUpperCase())return match;
  replaced++;
  return slashes.slice(1)+String.fromCharCode(code);
});
const restored=compact.replace(/[가-힣]/g,c=>"\\u"+c.charCodeAt(0).toString(16).toUpperCase());
if(restored!==source)throw Error("UTF-8 compaction is not reversible; refusing to write");
writeFileSync(file,compact,"utf8");
console.log(JSON.stringify({event:"RIAN_UTF8_COMPACTION",file,replaced,before_bytes:Buffer.byteLength(source),after_bytes:Buffer.byteLength(compact)}));
