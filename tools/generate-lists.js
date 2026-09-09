#!/usr/bin/env node

/**
 * generate-lists.js — IC Security Project (pipeline SAST)
 *
 * Lê datasets/cve-metadata.csv (produzido por extract-urls.js) e gera em
 * datasets/listas/:
 *
 *   - cves-sast.txt            → lista completa, 1 linha por CVE
 *   - cves-sast-batch-aa..     → mesma lista fatiada em batches de 30
 *   - cves-sast-teste          → 5 CVEs escolhidos a dedo (smoke test)
 *
 * Formato de linha (6 campos, separados por vírgula):
 *
 *   CVE,URL,COMMIT,CWES,FILEPATH,FILELINE
 *
 *   COMMIT   = PrePatchCommit (commit VULNERÁVEL — é dele que se faz checkout)
 *   CWES     = separados por '|', normalizados para 3 dígitos (CWE-79 → CWE-079)
 *   FILEPATH = caminho do arquivo vulnerável segundo o benchmark (ground truth)
 *   FILELINE = linha(s) vulnerável(is), separadas por '|' como os CWEs, ou vazio
 *
 * A unidade do pipeline é o CVE, não o repositório: o mesmo repo aparece em
 * vários CVEs com commits diferentes (bootstrap 7x, lodash 5x, ...), e cada
 * um gera uma análise independente.
 *
 * Validações abortam a geração (exit 1) — é melhor não gerar lista nenhuma
 * do que rodar 223 análises em cima de uma lista silenciosamente corrompida.
 *
 * Uso:
 *   node tools/generate-lists.js            # primeira geração
 *   node tools/generate-lists.js --force    # regerar, apagando os batches antigos
 *
 * Sem --force, se já houver batches na pasta, o gerador lista o que seria
 * removido e aborta sem escrever nada.
 */

const fs   = require('fs');
const path = require('path');

const ROOT      = path.join(__dirname, '..');
const IN_CSV    = path.join(ROOT, 'datasets', 'cve-metadata.csv');
const OUT_DIR   = path.join(ROOT, 'datasets', 'listas');

const OUT_FULL  = path.join(OUT_DIR, 'cves-sast.txt');
const OUT_TESTE = path.join(OUT_DIR, 'cves-sast-teste');
const BATCH_PREFIX = path.join(OUT_DIR, 'cves-sast-batch-');

const EXPECTED_RECORDS = 223;   // total de CVEs do benchmark da OpenSSF
const BATCH_SIZE       = 30;

const BATCH_RE = /^cves-sast-batch-[a-z]{2}$/;

// ── argumentos ──
const argv    = process.argv.slice(2);
const FORCE   = argv.includes('--force');
const unknown = argv.filter(a => a !== '--force');
if (unknown.length) {
  console.error(`\n❌ Argumento desconhecido: ${unknown.join(' ')}`);
  console.error('   Uso: node tools/generate-lists.js [--force]\n');
  process.exit(2);
}

/** CVEs do batch de teste, na ordem em que devem aparecer no arquivo. */
const TESTE_CVES = [
  'CVE-2018-14040',   // bootstrap — commit A
  'CVE-2018-14041',   // bootstrap — commit B (mesmo repo, commit DIFERENTE)
  'CVE-2019-10744',   // lodash — repo grande, mede o ganho do fetch raso
  'CVE-2016-1000229', // linxiaowu66/swagger-ui — não confundir com swagger-api/swagger-ui
  'CVE-2017-16042',   // tj/node-growl — repo pequeno, CVE antigo
];

// ─────────────────────────────────────────────────────────────
// Parser de CSV
// ─────────────────────────────────────────────────────────────

/**
 * Parser CSV (RFC 4180) tolerante a aspas não escapadas dentro de campo citado.
 *
 * A tolerância é defesa em profundidade: o extract-urls.js já escapa as aspas
 * corretamente (aspa interna → aspa dupla), mas versões anteriores dele
 * produziam 7 linhas malformadas — as explicações que citam «"Zip Slip"»:
 *
 *   ..."Arbitrary file write during zip extraction ("Zip Slip")",...
 *
 * Regra adotada: uma aspa dentro de campo citado só fecha o campo se o
 * próximo caractere for vírgula ou fim de linha; caso contrário é tratada
 * como aspa literal. Assim um CSV antigo ou gerado por outra ferramenta
 * ainda é lido com as colunas alinhadas, em vez de falhar silenciosamente.
 */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let i = 0;

  const src = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  const endField = () => { row.push(field); field = ''; };
  const endRow   = () => { endField(); rows.push(row); row = []; };

  while (i < src.length) {
    const ch = src[i];

    if (inQuotes) {
      if (ch === '"') {
        const next = src[i + 1];
        if (next === '"') { field += '"'; i += 2; continue; }      // aspa escapada
        if (next === undefined || next === ',' || next === '\n') { // fecha de verdade
          inQuotes = false; i++; continue;
        }
        field += '"'; i++; continue;                               // aspa literal (tolerância)
      }
      field += ch; i++; continue;
    }

    if (ch === '"' && field === '') { inQuotes = true; i++; continue; }
    if (ch === ',')  { endField(); i++; continue; }
    if (ch === '\n') { endRow();   i++; continue; }
    field += ch; i++;
  }

  // última linha (o CSV do extract-urls.js não termina com newline)
  if (field !== '' || row.length > 0) endRow();

  return rows.filter(r => !(r.length === 1 && r[0].trim() === ''));
}

// ─────────────────────────────────────────────────────────────
// Normalização
// ─────────────────────────────────────────────────────────────

/**
 * Normaliza um CWE para 'CWE-' + 3 dígitos com zero à esquerda.
 * O benchmark mistura as duas formas (CWE-79 e CWE-079 coexistem), o que
 * quebraria qualquer agregação por CWE nas métricas.
 */
function normalizeCwe(raw) {
  const s = String(raw).trim();
  const m = /^CWE-(\d+)$/i.exec(s);
  if (!m) return { ok: false, value: s };
  return { ok: true, value: 'CWE-' + m[1].padStart(3, '0') };
}

function normalizeCweList(rawField, cve, errors) {
  const parts = String(rawField || '')
    .split(/[,|]/)
    .map(s => s.trim())
    .filter(Boolean);

  const out = [];
  for (const p of parts) {
    const { ok, value } = normalizeCwe(p);
    if (!ok) {
      errors.push(`${cve}: CWE em formato inesperado: "${p}"`);
      continue;
    }
    if (!out.includes(value)) out.push(value);   // dedup preservando a ordem
  }
  return out;
}

// ─────────────────────────────────────────────────────────────
// Leitura + validação
// ─────────────────────────────────────────────────────────────

function fail(title, problems) {
  console.error(`\n❌ ${title}`);
  for (const p of problems) console.error(p === '' ? '' : `   • ${p}`);
  console.error('\nNenhum arquivo foi gerado.\n');
  process.exit(1);
}

// ── Pré-voo: batches de execuções anteriores ──
//
// Regerar apaga os batches antigos, senão um dataset menor deixaria órfãos
// para trás. Como são arquivos versionados, a remoção exige --force: sem a
// flag o gerador lista o que removeria e aborta aqui, antes de ler o CSV e
// antes de escrever qualquer coisa.
const staleBatches = fs.existsSync(OUT_DIR)
  ? fs.readdirSync(OUT_DIR).filter(f => BATCH_RE.test(f)).sort()
  : [];

if (staleBatches.length && !FORCE) {
  fail(`Já existem ${staleBatches.length} batch(es) em datasets/listas/ — nada foi escrito`, [
    ...staleBatches.map(f => `seria removido: datasets/listas/${f}`),
    '',
    'Regerar apaga esses arquivos antes de escrever os novos.',
    'Confirme com:  node tools/generate-lists.js --force',
  ]);
}

if (!fs.existsSync(IN_CSV)) {
  fail('CSV de entrada não encontrado', [
    `Esperado em: ${IN_CSV}`,
    'Rode antes:  node tools/extract-urls.js',
  ]);
}

const rows = parseCsv(fs.readFileSync(IN_CSV, 'utf8'));
if (rows.length === 0) fail('CSV vazio', [IN_CSV]);

const EXPECTED_HEADER = [
  'CVE', 'Repository', 'PrePatchCommit', 'PostPatchCommit',
  'CWEs', 'Explanation', 'FilePath', 'FileLine',
];

const header = rows[0].map(h => h.trim());
if (header.join(',') !== EXPECTED_HEADER.join(',')) {
  fail('Cabeçalho do CSV diferente do esperado', [
    `esperado: ${EXPECTED_HEADER.join(',')}`,
    `lido:     ${header.join(',')}`,
  ]);
}

const dataRows = rows.slice(1);
const errors   = [];
const warnings = [];       // não-bloqueantes (ver PostPatchCommit abaixo)
const pathWarnings = [];   // não-bloqueantes (ver FilePath anômalo abaixo)
const records  = [];
const seenCve  = new Map();

dataRows.forEach((cols, idx) => {
  const lineNo = idx + 2;   // +1 do cabeçalho, +1 porque é 1-indexado

  if (cols.length !== EXPECTED_HEADER.length) {
    errors.push(`linha ${lineNo}: ${cols.length} campos, esperado ${EXPECTED_HEADER.length}`);
    return;
  }

  const [cve, repository, prePatch, postPatch, cwesRaw, , filePath, fileLine] =
    cols.map(c => c.trim());

  // CVE presente e único
  if (!cve) {
    errors.push(`linha ${lineNo}: CVE vazio`);
    return;
  }
  if (seenCve.has(cve)) {
    errors.push(`linha ${lineNo}: CVE duplicado "${cve}" (já visto na linha ${seenCve.get(cve)})`);
    return;
  }
  seenCve.set(cve, lineNo);

  // URL do repositório
  if (!repository) errors.push(`${cve}: Repository vazio`);

  // Commit vulnerável: 40 chars hex minúsculos. É dele que se faz checkout,
  // então qualquer desvio aqui é erro fatal.
  if (!/^[0-9a-f]{40}$/.test(prePatch)) {
    errors.push(`${cve}: PrePatchCommit inválido "${prePatch}" (${prePatch.length} chars, esperado 40 hex)`);
  }

  // PostPatchCommit fora do padrão é AVISO, não erro: o campo não entra nas
  // listas nem no pipeline SAST (serve só para análise futura de diff), e há
  // defeitos conhecidos no próprio benchmark da OpenSSF.
  if (postPatch && !/^[0-9a-f]{40}$/.test(postPatch)) {
    warnings.push({ cve, value: postPatch, len: postPatch.length });
  } else if (!postPatch) {
    warnings.push({ cve, value: '(vazio)', len: 0 });
  }

  const cwes = normalizeCweList(cwesRaw, cve, errors);
  for (const c of cwes) {
    if (!/^CWE-\d{3}$/.test(c)) {
      errors.push(`${cve}: CWE fora do formato CWE-NNN após normalização: "${c}"`);
    }
  }

  // FilePath: obrigatório. É o ground truth de localização usado na etapa 3
  // para decidir se um achado da ferramenta corresponde à vulnerabilidade real.
  // Vazio aqui significa que o extract-urls.js degradou silenciosamente um
  // prePatch.weaknesses[0].location.file ausente — o CVE entraria na lista e
  // seria analisado, mas viraria falso negativo garantido nas métricas.
  if (!filePath) {
    errors.push(`${cve}: FilePath vazio (ground truth de localização ausente)`);
  }

  // FilePath anômalo é AVISO, não erro: o caminho é usado como veio, e a
  // normalização é do normalizer (tools/normalize.py), não daqui. O aviso
  // existe para que a anomalia apareça NA GERAÇÃO, e não três etapas adiante
  // — mesmo tratamento dado ao PostPatchCommit malformado.
  //
  // Hoje dispara em 1 dos 223: CVE-2019-12041 declara "/index.js", com barra
  // inicial, no próprio benchmark da OpenSSF. Sem normalizar, o caminho não
  // casa com saída de ferramenta alguma e o CVE vira falso negativo garantido.
  if (filePath) {
    const anomalias = [];
    if (filePath.startsWith('/'))            anomalias.push('barra inicial');
    if (filePath.startsWith('./'))           anomalias.push('./ inicial');
    if (filePath.split('/').includes('..'))  anomalias.push('.. no caminho');
    if (filePath.includes('\\'))             anomalias.push('barra invertida');
    if (filePath.includes('://'))            anomalias.push('esquema de URI');
    if (filePath.includes('//'))             anomalias.push('barra dupla');
    if (filePath.endsWith('/'))              anomalias.push('barra final');
    if (filePath !== filePath.trim())        anomalias.push('espaço inicial ou final');
    if (filePath.startsWith('~'))            anomalias.push('~ inicial');
    if (/^[A-Za-z]:/.test(filePath))         anomalias.push('letra de unidade');
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f]/.test(filePath))        anomalias.push('caractere de controle');
    if (anomalias.length) {
      pathWarnings.push({ cve, value: filePath, why: anomalias.join(', ') });
    }
  }

  // FileLine: uma ou mais linhas separadas por '|', ou vazio.
  //
  // Multivalorado porque 3 CVEs têm várias weaknesses — vários pontos da MESMA
  // vulnerabilidade, sempre no mesmo arquivo (ver notas do README). Guardar
  // todas evita contar como falso negativo um acerto em linha diferente da
  // primeira. FilePath continua escalar: o extract-urls.js aborta se algum dia
  // as weaknesses de um CVE apontarem para arquivos diferentes.
  //
  // Vazio é tolerado de propósito, ao contrário de FilePath: sem a linha ainda
  // dá para cruzar achados por arquivo, que é a granularidade mínima útil.
  if (fileLine !== '' && !/^\d+(\|\d+)*$/.test(fileLine)) {
    errors.push(`${cve}: FileLine deve ser linhas numéricas separadas por '|' ou vazio: "${fileLine}"`);
  }
  const fileLines = fileLine === '' ? [] : fileLine.split('|');
  if (new Set(fileLines).size !== fileLines.length) {
    errors.push(`${cve}: FileLine com linha repetida: "${fileLine}"`);
  }

  // Campos que iriam quebrar o formato de 6 campos separados por vírgula
  for (const [nome, valor] of [['Repository', repository], ['FilePath', filePath]]) {
    if (valor.includes(',')) {
      errors.push(`${cve}: ${nome} contém vírgula, quebraria o formato de 6 campos: "${valor}"`);
    }
  }

  records.push({ cve, repository, commit: prePatch, cwes, filePath, fileLine, fileLines });
});

if (records.length !== EXPECTED_RECORDS) {
  errors.push(`total de registros lidos = ${records.length}, esperado ${EXPECTED_RECORDS}`);
}

if (errors.length) fail(`Validação falhou (${errors.length} problema(s))`, errors);

if (warnings.length) {
  console.warn(`\n⚠️  AVISO (não-bloqueante): ${warnings.length} PostPatchCommit fora do padrão de 40 hex`);
  for (const w of warnings) {
    console.warn(`   • ${w.cve}: "${w.value}" (${w.len} chars)`);
  }
  console.warn('   Defeito presente no benchmark original da OpenSSF, não introduzido aqui.');
  console.warn('   O campo não é usado pelo pipeline SAST — a geração continua normalmente.');
}

if (pathWarnings.length) {
  console.warn(`\n⚠️  AVISO (não-bloqueante): ${pathWarnings.length} FilePath anômalo`);
  for (const w of pathWarnings) {
    console.warn(`   • ${w.cve}: "${w.value}" (${w.why})`);
  }
  console.warn('   Defeito presente no benchmark original da OpenSSF, não introduzido aqui.');
  console.warn('   O caminho entra na lista COMO VEIO; quem normaliza é tools/normalize.py,');
  console.warn('   que grava o valor original em gt_file_path_original. A geração continua.');
}

// ─────────────────────────────────────────────────────────────
// Geração
// ─────────────────────────────────────────────────────────────

const toLine = r => [
  r.cve,
  r.repository,
  r.commit,
  r.cwes.join('|'),
  r.filePath,
  r.fileLine,
].join(',');

/** Escreve uma lista sempre com newline final (o loop `while read` do bash
 *  descarta a última linha se ela não terminar com \n). */
function writeList(file, lines) {
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

fs.mkdirSync(OUT_DIR, { recursive: true });

for (const f of staleBatches) fs.unlinkSync(path.join(OUT_DIR, f));

const allLines = records.map(toLine);
writeList(OUT_FULL, allLines);

// batches ---------------------------------------------------------------
const suffix = n => {
  const a = 'abcdefghijklmnopqrstuvwxyz';
  if (n >= a.length * a.length) {
    fail('Batches demais para sufixo de 2 letras', [`índice ${n}`]);
  }
  return a[Math.floor(n / a.length)] + a[n % a.length];
};

const batches = [];
for (let i = 0; i < allLines.length; i += BATCH_SIZE) {
  const chunk = allLines.slice(i, i + BATCH_SIZE);
  const file  = BATCH_PREFIX + suffix(batches.length);
  writeList(file, chunk);
  batches.push({ file: path.basename(file), count: chunk.length });
}

// batch de teste --------------------------------------------------------
const byCve = new Map(records.map(r => [r.cve, r]));
const faltando = TESTE_CVES.filter(c => !byCve.has(c));
if (faltando.length) {
  fail('CVEs do batch de teste ausentes no CSV', faltando);
}
writeList(OUT_TESTE, TESTE_CVES.map(c => toLine(byCve.get(c))));

// ─────────────────────────────────────────────────────────────
// Resumo
// ─────────────────────────────────────────────────────────────

const semCwe   = records.filter(r => r.cwes.length === 0);
const multiLoc = records.filter(r => r.fileLines.length > 1);
const totalLocs = records.reduce((n, r) => n + r.fileLines.length, 0);
const cweFreq = new Map();
for (const r of records) for (const c of r.cwes) cweFreq.set(c, (cweFreq.get(c) || 0) + 1);

const bar = '═'.repeat(62);
console.log(`\n${bar}`);
console.log('✅ LISTAS GERADAS — todas as validações passaram');
console.log(bar);
console.log(`Origem                : datasets/cve-metadata.csv`);
console.log(`Registros lidos       : ${records.length} (esperado ${EXPECTED_RECORDS})`);
console.log(`Linhas geradas        : ${allLines.length}  → datasets/listas/cves-sast.txt`);
console.log(`CVEs sem CWE          : ${semCwe.length}${semCwe.length ? '  → ' + semCwe.map(r => r.cve).join(', ') : ''}`);
console.log(`                        (analisados normalmente; excluídos só nas métricas)`);
console.log(`Localizações totais   : ${totalLocs} em ${records.length} CVEs`);
console.log(`CVEs multi-localização: ${multiLoc.length}${multiLoc.length ? '  → ' + multiLoc.map(r => `${r.cve} (${r.fileLines.length})`).join(', ') : ''}`);
console.log(`CWEs distintos        : ${cweFreq.size}`);
console.log(`Repositórios distintos: ${new Set(records.map(r => r.repository)).size}`);
console.log(`Batches (máx ${BATCH_SIZE}/un.) : ${batches.length}`);
console.log('');
console.log('Distribuição por batch:');
for (const b of batches) {
  console.log(`  ${b.file.padEnd(22)} ${String(b.count).padStart(3)} linhas  ${'▇'.repeat(b.count)}`);
}
console.log(`  ${'cves-sast-teste'.padEnd(22)} ${String(TESTE_CVES.length).padStart(3)} linhas  ${'▇'.repeat(TESTE_CVES.length)}`);
console.log('');
console.log('Top 5 CWEs:');
[...cweFreq.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5)
  .forEach(([c, n]) => console.log(`  ${c}  ${String(n).padStart(3)} CVE(s)`));
console.log(`${bar}\n`);
