#!/usr/bin/env node

/**
 * extract-urls.js — OpenSSF CVE Benchmark
 *
 * Lê os JSONs de ../ossf-cve-benchmark/CVEs/ sem clonar nada e gera em ../datasets/:
 *   - cve-metadata.json     → metadados completos de cada CVE
 *   - cve-metadata.csv      → mesma coisa em CSV para abrir no Excel
 *
 * As listas de entrada do pipeline SAST são geradas por tools/generate-lists.js.
 *
 * Inclui prePatch (vulnerável) e postPatch (corrigido) para permitir
 * análise futura de falsos positivos e diffs de correção.
 */

const fs   = require('fs');
const path = require('path');

const ROOT          = path.join(__dirname, '..');
const CVE_DIR       = path.join(ROOT, 'ossf-cve-benchmark', 'CVEs');
const OUT_DIR       = path.join(ROOT, 'datasets');
const OUT_JSON      = path.join(OUT_DIR, 'cve-metadata.json');
const OUT_CSV       = path.join(OUT_DIR, 'cve-metadata.csv');

const cveFiles = fs.readdirSync(CVE_DIR).filter(f => f.endsWith('.json'));
console.log(`\n📦 CVEs encontrados: ${cveFiles.length}\n`);

const results = [];
const multiFile = [];   // CVEs cujas weaknesses apontam para arquivos diferentes

for (const file of cveFiles) {
  const cveData     = JSON.parse(fs.readFileSync(path.join(CVE_DIR, file), 'utf8'));
  const cveName     = file.replace('.json', '');
  const repoUrl     = cveData.repository;
  const prePatch    = cveData.prePatch?.commit;
  const postPatch   = cveData.postPatch?.commit || '';
  const cwes        = (cveData.CWEs || []).join(', ');
  const weaknesses  = cveData.prePatch?.weaknesses || [];
  const explanation = weaknesses[0]?.explanation || '';

  // Um CVE pode ter várias weaknesses — vários pontos da MESMA vulnerabilidade
  // (3 CVEs no benchmark: 2, 5 e 6 localizações). Preservar todas as linhas
  // evita contar como falso negativo um acerto legítimo em linha diferente da
  // primeira. O schema do benchmark não põe CWE na weakness: os CWEs são do
  // CVE inteiro, então nada se perde ao achatar as linhas em um campo só.
  const arquivos = [...new Set(weaknesses.map(w => w?.location?.file).filter(f => f != null))];

  // FilePath é escalar: só faz sentido se todas as weaknesses estiverem no
  // mesmo arquivo. Vale para os 223 hoje; se um dia não valer, abortamos em
  // vez de descartar em silêncio as localizações dos outros arquivos.
  if (arquivos.length > 1) {
    multiFile.push({ cve: cveName, arquivos });
  }

  const file_path = arquivos[0] || '';

  // '??' e não '||': a linha é um número, e '0 || ""' viraria string vazia.
  // Hoje nenhum CVE tem line === 0 (linhas são 1-based), mas '??' só cai no
  // fallback para null/undefined, que é exatamente a condição pretendida.
  const linhas = weaknesses
    .map(w => w?.location?.line ?? '')
    .filter(l => l !== '');
  const file_line = [...new Set(linhas)].join('|');   // '|' como nos CWEs

  console.log(`  ${cveName} → ${repoUrl}${linhas.length > 1 ? `  (${linhas.length} localizações)` : ''}`);

  results.push({
    cve: cveName,
    repository: repoUrl,
    prePatchCommit: prePatch,     // commit vulnerável (usado nas análises)
    postPatchCommit: postPatch,   // commit corrigido (para análise futura)
    cwes,
    explanation,
    file_path,
    file_line,
  });
}

if (multiFile.length) {
  console.error(`\n❌ ${multiFile.length} CVE(s) com weaknesses em arquivos diferentes.`);
  console.error('   FilePath é escalar e não consegue representar isso sem perder dados.');
  for (const m of multiFile) {
    console.error(`   • ${m.cve}: ${m.arquivos.join(', ')}`);
  }
  console.error('\nNenhum arquivo foi gerado.\n');
  process.exit(1);
}

// cve-metadata.json
fs.writeFileSync(OUT_JSON, JSON.stringify(results, null, 2));

// cve-metadata.csv
//
// Campo entre aspas conforme RFC 4180: aspas internas viram aspas duplas.
// Sem isso, as explicações que citam «"Zip Slip"» geravam CSV malformado e
// desalinhavam as colunas seguintes (FilePath/FileLine) em 7 linhas.
const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;

const csvHeader = 'CVE,Repository,PrePatchCommit,PostPatchCommit,CWEs,Explanation,FilePath,FileLine';
const csvRows   = results.map(r => [
  r.cve,
  r.repository,
  r.prePatchCommit,
  r.postPatchCommit,
  q(r.cwes),
  q(r.explanation),
  q(r.file_path),
  r.file_line,
].join(','));
fs.writeFileSync(OUT_CSV, [csvHeader, ...csvRows].join('\n'));

console.log('\n' + '═'.repeat(60));
console.log('✅ CONCLUÍDO');
console.log('═'.repeat(60));
console.log(`Total de CVEs:    ${results.length}`);
console.log(`📄 datasets/cve-metadata.json → metadados completos (prePatch + postPatch)`);
console.log(`📄 datasets/cve-metadata.csv  → para abrir no Excel`);
