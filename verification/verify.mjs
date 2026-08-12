import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';

const repoRoot = path.resolve(import.meta.dirname, '..');
const artifactRoot = path.join(repoRoot, 'artifacts');
const evidenceRoot = path.join(repoRoot, 'verification', 'evidence');
const npmCli = process.env.npm_execpath;
const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const attachments = ['输入数据包.zip', 'reference.zip', '关键标准答案.xlsx', '任务规格转化.xlsx'];
const expectedReference = [
  'output/reports/alert_rollup.csv',
  'output/reports/normalized_violations.csv',
  'output/reports/source_lookup.csv',
  'output/reports/suppressed_reports.csv',
  'output/src/triage_csp_reports.mjs',
].sort();
const reportKeys = {
  'output/reports/normalized_violations.csv': ['report_id'],
  'output/reports/source_lookup.csv': ['report_id'],
  'output/reports/suppressed_reports.csv': ['line_no'],
  'output/reports/alert_rollup.csv': ['first_report_id'],
};

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sha256File = (file) => sha256(fs.readFileSync(file));
const assert = (value, message) => { if (!value) throw new Error(message); };

function parseZipBytes(data) {
  const files = new Map(); let offset = 0;
  while (offset + 30 <= data.length) {
    if (data.readUInt32LE(offset) !== 0x04034b50) break;
    const flags = data.readUInt16LE(offset + 6); const method = data.readUInt16LE(offset + 8);
    const compressedSize = data.readUInt32LE(offset + 18); const uncompressedSize = data.readUInt32LE(offset + 22);
    const nameLength = data.readUInt16LE(offset + 26); const extraLength = data.readUInt16LE(offset + 28);
    assert(!(flags & 0x08), 'ZIP数据描述符不受支持');
    const name = data.subarray(offset + 30, offset + 30 + nameLength).toString('utf8').replaceAll('\\', '/');
    const start = offset + 30 + nameLength + extraLength; const compressed = data.subarray(start, start + compressedSize);
    if (!name.endsWith('/')) {
      const body = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : null;
      assert(body && body.length === uncompressedSize, `无法解压${name}`); files.set(name, body);
    }
    offset = start + compressedSize;
  }
  return files;
}
const parseZip = (file) => parseZipBytes(fs.readFileSync(file));
async function extractZip(file, destination) {
  for (const [name, bytes] of parseZip(file)) {
    const target = path.resolve(destination, name); assert(target.startsWith(path.resolve(destination) + path.sep), `非法ZIP路径${name}`);
    await fsp.mkdir(path.dirname(target), { recursive: true }); await fsp.writeFile(target, bytes);
  }
}
function workbookSheets(file) {
  const workbook = parseZipBytes(fs.readFileSync(file)).get('xl/workbook.xml')?.toString('utf8') ?? '';
  return [...workbook.matchAll(/<(?:[A-Za-z]+:)?sheet[^>]+name="([^"]+)"/gu)].map((match) => match[1]);
}
async function run(command, args, cwd) {
  const started = Date.now();
  return await new Promise((resolve) => {
    let child;
    try { child = spawn(command, args, { cwd, env: process.env, windowsHide: true }); }
    catch (error) { resolve({ code: 1, stdout: '', stderr: error.stack ?? error.message, elapsed_ms: Date.now() - started }); return; }
    let stdout = ''; let stderr = ''; let settled = false;
    child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => { if (!settled) { settled = true; resolve({ code: 1, stdout, stderr: `${stderr}${error.stack ?? error.message}`, elapsed_ms: Date.now() - started }); } });
    child.on('exit', (code) => { if (!settled) { settled = true; resolve({ code: code ?? 1, stdout, stderr, elapsed_ms: Date.now() - started }); } });
  });
}
async function runNpm(args, cwd) { return npmCli ? await run(process.execPath, [npmCli, ...args], cwd) : await run(npmCommand, args, cwd); }
function treeDigest(root, ignored = new Set()) {
  const lines = [];
  function visit(current, prefix = '') {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((a, b) => a.name.localeCompare(b.name))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name; if (ignored.has(relative.split('/')[0])) continue;
      const full = path.join(current, entry.name); if (entry.isDirectory()) visit(full, relative); else lines.push(`${relative}\0${sha256File(full)}`);
    }
  }
  visit(root); return sha256(Buffer.from(lines.join('\n')));
}
function parseCsv(text) {
  const rows = []; let row = []; let cell = ''; let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) { if (char === '"' && text[index + 1] === '"') { cell += '"'; index += 1; } else if (char === '"') quoted = false; else cell += char; }
    else if (char === '"') quoted = true; else if (char === ',') { row.push(cell); cell = ''; }
    else if (char === '\n') { row.push(cell.replace(/\r$/u, '')); rows.push(row); row = []; cell = ''; } else cell += char;
  }
  if (cell || row.length) { row.push(cell.replace(/\r$/u, '')); rows.push(row); }
  const headers = rows.shift() ?? []; return rows.filter((values) => values.some((value) => value !== '')).map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])));
}
function normalizedRows(file, text) {
  const keys = reportKeys[file]; const rows = parseCsv(text);
  return rows.toSorted((a, b) => keys.map((key) => String(a[key]).localeCompare(String(b[key]), undefined, { numeric: true })).find((value) => value !== 0) ?? 0);
}
function classifyExecutable(name, bytes) {
  const lower = name.toLowerCase();
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes.subarray(1, 4).toString('ascii') === 'ELF') return 'linux_elf';
  if (bytes.length >= 4 && [0xfeedface, 0xfeedfacf, 0xcafebabe].includes(bytes.readUInt32BE(0))) return 'macos_macho';
  if (/\.(?:sh|bash|so)(?:\.|$)/u.test(lower)) return 'posix_member';
  if (/^#!.*(?:ba|z|k)?sh/mu.test(bytes.subarray(0, 128).toString('utf8'))) return 'posix_shebang';
  return null;
}
async function prepare(label, mutate) {
  const root = path.join(os.tmpdir(), label); await fsp.rm(root, { recursive: true, force: true }); await fsp.mkdir(root, { recursive: true });
  await extractZip(path.join(artifactRoot, '输入数据包.zip'), root);
  const inputRoot = path.join(root, 'input_data'); const reference = parseZip(path.join(artifactRoot, 'reference.zip'));
  await fsp.mkdir(path.join(inputRoot, 'output', 'src'), { recursive: true });
  await fsp.writeFile(path.join(inputRoot, 'output', 'src', 'triage_csp_reports.mjs'), reference.get('output/src/triage_csp_reports.mjs'));
  if (mutate) await mutate(inputRoot);
  return { root, inputRoot, outputRoot: path.join(inputRoot, 'output'), reference };
}
function outputPaths(root) {
  const paths = [];
  function walk(current, prefix = '') { for (const entry of fs.readdirSync(current, { withFileTypes: true })) { const relative = prefix ? `${prefix}/${entry.name}` : entry.name; if (entry.isDirectory()) walk(path.join(current, entry.name), relative); else paths.push(`output/${relative}`); } }
  walk(root); return paths.sort();
}
function compareReference(outputRoot, reference) {
  assert(JSON.stringify(outputPaths(outputRoot)) === JSON.stringify(expectedReference), '输出成员与Reference不一致');
  const semantic = crypto.createHash('sha256');
  for (const file of expectedReference) {
    const actual = fs.readFileSync(path.join(path.dirname(outputRoot), file)); const expected = reference.get(file);
    if (file.endsWith('.csv')) {
      const actualRows = normalizedRows(file, actual.toString('utf8')); const expectedRows = normalizedRows(file, expected.toString('utf8'));
      assert(JSON.stringify(actualRows) === JSON.stringify(expectedRows), `${file}与Reference不一致`); semantic.update(JSON.stringify(actualRows));
    } else {
      const actualText = actual.toString('utf8').replaceAll('\r\n', '\n'); const expectedText = expected.toString('utf8').replaceAll('\r\n', '\n');
      assert(actualText === expectedText, `${file}与Reference不一致`); semantic.update(actualText);
    }
  }
  return semantic.digest('hex');
}

await fsp.rm(evidenceRoot, { recursive: true, force: true }); await fsp.mkdir(evidenceRoot, { recursive: true });
assert(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', '该验证器只接受GitHub托管Windows运行');
const attachmentSha256 = Object.fromEntries(attachments.map((name) => [name, sha256File(path.join(artifactRoot, name))]));
const inputMembers = parseZip(path.join(artifactRoot, '输入数据包.zip'));
const executableScan = [...inputMembers].map(([name, bytes]) => ({ name, classification: classifyExecutable(name, bytes) })).filter((item) => item.classification);
assert(executableScan.length === 0, `输入包含平台专用可执行成员：${JSON.stringify(executableScan)}`);
const referenceMembers = [...parseZip(path.join(artifactRoot, 'reference.zip')).keys()].sort(); assert(JSON.stringify(referenceMembers) === JSON.stringify(expectedReference), 'Reference成员错误');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx'))) === JSON.stringify(['交付物答案清单', '固定字段答案', '固定集合答案', '固定数值答案', '允许变体答案']), '关键标准答案Sheet错误');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx'))) === JSON.stringify(['任务规格转化']), '任务规格Sheet错误');
const solutionText = parseZip(path.join(artifactRoot, 'reference.zip')).get('output/src/triage_csp_reports.mjs').toString('utf8');
assert(!/\bR\d{3}\b|web-2026\.07\.28|reference\.zip|https?:\/\/|node:(?:http|https|net|tls)|\bfetch\s*\(/u.test(solutionText), '完成版模块含样本主键、固定release、Reference或外部网络调用');
const staticReview = JSON.parse(fs.readFileSync(path.join(repoRoot, 'qa', 'static-review.json'), 'utf8'));
const scoreAnswerLeak = JSON.parse(fs.readFileSync(path.join(repoRoot, 'qa', 'score-answer-leak.json'), 'utf8'));
const candidateScore = fs.readFileSync(path.join(repoRoot, 'task', '评分表.txt'), 'utf8');
const scoreLeakPatterns = [
  /\bR\d{3}\b/gu,
  /(?:完整|全部)(?:通过|拒绝|压制|保留|结果)(?:集合|清单)/gu,
  /(?:固定|共计|总计|恰好|正好)\s*\d+\s*(?:行|条|组|个|份)/gu,
  /(?:依次|分别)为[^。\n]+/gu,
  /\b[a-f0-9]{12}\b/giu,
  /(?:source_path|源码路径)[^。\n]*第\s*\d+\s*行/gu,
  /(?:金额|费用|价格|人民币|美元|元整)/gu,
];
const currentScoreLeakHits = scoreLeakPatterns.flatMap((pattern) => [...candidateScore.matchAll(pattern)].map((match) => match[0]));
assert(staticReview.result === 'PASS' && staticReview.task_spec_column_count === 2, '静态审计或任务规格列数不合格');
assert(scoreAnswerLeak.pass === true && Array.isArray(scoreAnswerLeak.hits) && scoreAnswerLeak.hits.length === 0 && currentScoreLeakHits.length === 0, `候选人评分表泄露样本答案：${JSON.stringify(currentScoreLeakHits)}`);

const cleanRuns = [];
for (const label of ['Q10398 第一次 空目录', 'Q10398 第二次 中文 空格目录']) {
  const prepared = await prepare(label); const before = treeDigest(prepared.inputRoot, new Set(['output'])); const result = await runNpm(['run', 'process'], prepared.inputRoot);
  assert(result.code === 0, `${label}执行失败\n${result.stdout}\n${result.stderr}`); const after = treeDigest(prepared.inputRoot, new Set(['output'])); assert(before === after, `${label}修改了输入`);
  const semantic = compareReference(prepared.outputRoot, prepared.reference); cleanRuns.push({ directory_label: label, exit_code: result.code, input_digest_before: before, input_digest_after: after, semantic_digest: semantic, elapsed_ms: result.elapsed_ms });
}
assert(cleanRuns[0].semantic_digest === cleanRuns[1].semantic_digest, '两次结构化结果不一致');

const crlf = await prepare('Q10398 CRLF 上报', async (inputRoot) => { const file = path.join(inputRoot, 'data', 'csp_reports.jsonl'); const text = await fsp.readFile(file, 'utf8'); await fsp.writeFile(file, text.replace(/\r?\n/gu, '\r\n')); });
let result = await runNpm(['run', 'process'], crlf.inputRoot); assert(result.code === 0, `CRLF上报执行失败\n${result.stdout}\n${result.stderr}`);
const crlfDigest = compareReference(crlf.outputRoot, crlf.reference); assert(crlfDigest === cleanRuns[0].semantic_digest, 'CRLF上报改变业务结果');

const mutation = await prepare('Q10398 允许域名变化', async (inputRoot) => { const file = path.join(inputRoot, 'rules', 'csp_triage_policy.json'); const value = JSON.parse(await fsp.readFile(file, 'utf8')); value.allowed_blocked_hosts.push('evil.test'); await fsp.writeFile(file, `${JSON.stringify(value, null, 2)}\n`); });
result = await runNpm(['run', 'process'], mutation.inputRoot); assert(result.code === 0, `允许域名变化执行失败\n${result.stdout}\n${result.stderr}`);
const mutatedSuppressed = normalizedRows('output/reports/suppressed_reports.csv', fs.readFileSync(path.join(mutation.outputRoot, 'reports', 'suppressed_reports.csv'), 'utf8'));
const r001 = mutatedSuppressed.find((row) => row.report_id === 'R001'); const r003 = mutatedSuppressed.find((row) => row.report_id === 'R003');
assert(r001?.reason === 'allowed_blocked_host' && r003?.reason === 'allowed_blocked_host' && !mutatedSuppressed.some((row) => row.reason === 'duplicate_fingerprint'), '允许域名变化未按策略联动');
const mutatedNormalized = normalizedRows('output/reports/normalized_violations.csv', fs.readFileSync(path.join(mutation.outputRoot, 'reports', 'normalized_violations.csv'), 'utf8'));
assert(mutatedNormalized.length === 3 && !mutatedNormalized.some((row) => ['R001', 'R003'].includes(row.report_id)), '允许域名变化后的主流程不正确');

const negative = await prepare('Q10398 缺少source map', async (inputRoot) => { await fsp.rm(path.join(inputRoot, 'source_maps', 'app.map.json')); });
result = await runNpm(['run', 'process'], negative.inputRoot); const reportsAbsent = !fs.existsSync(path.join(negative.outputRoot, 'reports'));
assert(result.code !== 0 && reportsAbsent, '无效输入没有失败关闭');

const evidence = {
  schema_version: 1, task_asset_id: 'node_csp_source_triage', result: 'PASS', generated_at_utc: new Date().toISOString(), git_commit_sha: process.env.GITHUB_SHA, workflow_run_id: process.env.GITHUB_RUN_ID,
  runner: { os: process.env.RUNNER_OS, arch: process.env.RUNNER_ARCH, image_os: process.env.ImageOS, image_version: process.env.ImageVersion, node: process.version, powershell_hosted_workflow: true },
  software: { main: 'Node.js', executed: true, node: process.version }, attachment_sha256: attachmentSha256,
  workbook_checks: { answer_sheet_names: workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx')), specification_sheet_names: ['任务规格转化'], task_spec_column_count: staticReview.task_spec_column_count, candidate_score_answer_leak_hits: currentScoreLeakHits.length },
  platform_audit: { linux_executables: executableScan, linux_executables_executed: false, no_wsl_required: true, no_linux_container_required: true, no_posix_shell_required: true, no_unix_only_api_required: true, cross_platform_paths: true },
  clean_runs: cleanRuns, crlf_input: { file: 'data/csp_reports.jsonl', exit_code: 0, semantic_digest: crlfDigest, reference_match: true },
  positive_mutation: { changed_rule: 'allowed_blocked_hosts新增evil.test', exit_code: 0, r001_reason: r001?.reason, r003_reason: r003?.reason, duplicate_reason_absent: true, normalized_rows: mutatedNormalized.length },
  invalid_input: { removed_input: 'source_maps/app.map.json', exit_code: result.code, reports_absent: reportsAbsent },
  network: { installation_network_access: 'Node.js安装阶段', formal_run_network_access: 'none, local files and local Node.js only' },
};
await fsp.writeFile(path.join(evidenceRoot, 'windows-verification.json'), `${JSON.stringify(evidence, null, 2)}\n`); console.log(JSON.stringify(evidence, null, 2));
