// Lossless post-build size reduction for the Railway Function single-file Gateway.
// `bun build --minify` writes every Hangul syllable as a 6-byte \uXXXX escape.
// Inside JS string/template/regex literals the raw UTF-8 character (3 bytes) is
// the identical value, so this rewrites only odd-backslash 가-힣 escapes
// and proves the change is reversible byte-for-byte before saving.
//
// IMPORTANT: a bundle that starts with the `// @bun` pragma is loaded by Bun's
// pre-transpiled fast path, which decodes the file as Latin-1 (that is why the
// bundler escapes non-ASCII). CI showed raw UTF-8 Hangul turning into mojibake
// under that path. The pragma is therefore removed, so Bun parses the file as a
// normal UTF-8 module; CI then imports the result with Bun and compares Korean text.
import {readFileSync,writeFileSync} from "node:fs";

const file=process.argv[2];
if(!file)throw Error("usage: node compact-utf8.mjs <bundle.js>");
const source=readFileSync(file,"utf8");
if(/[가-힣]/.test(source))throw Error("Bundle already contains raw Hangul; refusing ambiguous rewrite");
if(/String\.raw`[^`]*\\u[A-F0-9]{4}/.test(source))throw Error("Escapes inside String.raw templates cannot be rewritten safely");
const PRAGMA=/^\/\/ @bun(?: [^\r\n]*)?\r?\n/;
const pragma=PRAGMA.exec(source)?.[0]||"";
if(pragma&&pragma.trimEnd()!=="// @bun")throw Error("Unexpected Bun pragma variant (bytecode/cjs); refusing to rewrite: "+JSON.stringify(pragma));
const body=source.slice(pragma.length);
let replaced=0;
const compact=body.replace(/(\\+)u([0-9A-Fa-f]{4})/g,(match,slashes,hex)=>{
  const code=parseInt(hex,16);
  if(slashes.length%2===0||code<0xAC00||code>0xD7A3||hex!==hex.toUpperCase())return match;
  replaced++;
  return slashes.slice(1)+String.fromCharCode(code);
});
const restored=pragma+compact.replace(/[가-힣]/g,c=>"\\u"+c.charCodeAt(0).toString(16).toUpperCase());
if(restored!==source)throw Error("UTF-8 compaction is not reversible; refusing to write");
writeFileSync(file,compact,"utf8");
console.log(JSON.stringify({event:"RIAN_UTF8_COMPACTION",file,replaced,bun_pragma_removed:!!pragma,before_bytes:Buffer.byteLength(source),after_bytes:Buffer.byteLength(compact)}));
