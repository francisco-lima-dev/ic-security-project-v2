// CONTROLE: cruza o ground truth do OpenSSF com as regras do Semgrep.
//
// Objetivo: testar se as "explanation" do ground truth sao vocabulario comum
// da area (apareceriam tambem no Semgrep) ou especificas do CodeQL.
//
// ATENCAO ao interpretar: o Semgrep nao usa nomes curtos de query como o
// CodeQL (usa id em slug e message em frase). Um match baixo e o esperado
// por diferenca de formato e prova pouco. Um match ALTO refutaria a hipotese.
// Este script serve para falsear, nao para confirmar.
//
// VIÉS DECLARADO: o cotejo e feito contra o catalogo ATUAL do Semgrep, nao o
// de 2020. O viés e CONSERVADOR — um catalogo menor, como o de 2020, daria
// correspondencia ainda MENOR que a nula medida. Trocar o catalogo por um de
// 2020 so reforcaria a conclusao, nunca a inverteria.
//
// ESCOLHA DE LINGUAGEM, declarada: este script permanece em Node, e nao foi
// portado para Python como o cotejo principal, PORQUE ele e o instrumento
// original da apuracao. Reescreve-lo faria o controle deixar de ser a coisa
// que produziu o numero registrado. A unica dependencia externa, js-yaml,
// esta fixada em package.json irmao — parser de YAML, nunca regex, que e a
// regra do projeto para contagem.
//
// MODIFICACAO DECLARADA em relacao ao original: a fonte dos CVEs passou a
// aceitar datasets/cve-metadata.csv, versionado. O original lia os JSON do
// clone do benchmark, que e ignorado pelo git e nao existe em clone limpo —
// era o que impedia um terceiro de reproduzir. O modo antigo continua
// disponivel, e quando as duas fontes estao presentes a equivalencia entre
// elas e CONFERIDA, nao presumida.
//
// Uso:
//   node cruza-semgrep.js <fonte-CVEs> <pasta-semgrep-rules>
// onde <fonte-CVEs> e o CSV versionado ou uma pasta de JSON do benchmark.
//
// Requer: npm install  (na pasta deste script)

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const dirCVEs = process.argv[2];
const dirSG = process.argv[3];

if (!dirCVEs || !dirSG) {
  console.error('Uso: node cruza-semgrep.js <pasta-CVEs> <pasta-semgrep-rules>');
  process.exit(1);
}

function chaveTexto(s) {
  return String(s)
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

// ---------- 1. Ler as regras do Semgrep ----------

function listaYaml(dir, acc = []) {
  let itens;
  try {
    itens = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return acc;
  }
  for (const item of itens) {
    if (item.name.startsWith('.')) continue;
    const p = path.join(dir, item.name);
    if (item.isDirectory()) listaYaml(p, acc);
    else if (/\.ya?ml$/.test(item.name)) acc.push(p);
  }
  return acc;
}

const regras = [];
let arquivosLidos = 0;
let arquivosComErro = 0;

for (const arquivo of listaYaml(dirSG)) {
  let doc;
  try {
    doc = yaml.load(fs.readFileSync(arquivo, 'utf8'));
  } catch (e) {
    arquivosComErro++;
    continue;
  }
  arquivosLidos++;
  if (!doc || !Array.isArray(doc.rules)) continue;

  for (const r of doc.rules) {
    if (!r || !r.id) continue;
    const meta = r.metadata || {};
    // O campo cwe pode ser string ou lista, e vem como "CWE-79: descricao".
    let cwes = meta.cwe || [];
    if (typeof cwes === 'string') cwes = [cwes];
    regras.push({
      id: String(r.id),
      message: String(r.message || '').replace(/\s+/g, ' ').trim(),
      cwes: cwes.map(String),
      arquivo: path.relative(dirSG, arquivo),
    });
  }
}

console.log(`Arquivos YAML lidos : ${arquivosLidos}  (erro de parse: ${arquivosComErro})`);
console.log(`Regras extraidas    : ${regras.length}\n`);

// Zero regras e "nao perguntei", nao "nao ha": pasta inexistente ou errada
// faz listaYaml devolver lista vazia, e o controle sairia 0 de 223 com
// exit 0 — o mesmo numero que o resultado legitimo.
if (!regras.length) {
  console.error(`ERRO: nenhuma regra lida em ${dirSG}; o controle nao vale.`);
  process.exit(2);
}

// Indices para os tres testes.
const porMessage = new Map(); // message inteira == explanation
const porIdFinal = new Map(); // ultimo segmento do id, com hifens virando espaco
for (const r of regras) {
  const km = chaveTexto(r.message);
  if (km && !porMessage.has(km)) porMessage.set(km, r);
  const ultimo = r.id.split('.').pop();
  const ki = chaveTexto(ultimo);
  if (ki && !porIdFinal.has(ki)) porIdFinal.set(ki, r);
}

// ---------- 2. Ler o ground truth ----------

// Parser de CSV conforme RFC 4180: sete CVEs de Zip Slip tem aspas no campo
// Explanation, escapadas por duplicacao. Um split(',') ingenuo os quebraria.
function leCsv(texto) {
  const linhas = [];
  let campo = '', linha = [], aspas = false;
  for (let i = 0; i < texto.length; i++) {
    const c = texto[i];
    if (aspas) {
      if (c === '"') {
        if (texto[i + 1] === '"') { campo += '"'; i++; } else aspas = false;
      } else campo += c;
    } else if (c === '"') aspas = true;
    else if (c === ',') { linha.push(campo); campo = ''; }
    else if (c === '\n') { linha.push(campo); linhas.push(linha); linha = []; campo = ''; }
    else if (c !== '\r') campo += c;
  }
  if (campo !== '' || linha.length) { linha.push(campo); linhas.push(linha); }
  const cab = linhas.shift();
  return linhas.filter((l) => l.length === cab.length)
    .map((l) => Object.fromEntries(cab.map((k, j) => [k, l[j]])));
}

function leDeJson(dir) {
  const out = [];
  for (const nome of fs.readdirSync(dir).filter((f) => f.endsWith('.json'))) {
    const d = JSON.parse(fs.readFileSync(path.join(dir, nome), 'utf8'));
    const w = ((d.prePatch && d.prePatch.weaknesses) || [])[0] || {};
    const exp = (w.explanation || '').trim();
    if (exp) out.push({ cve: d.CVE || nome.replace('.json', ''), explanation: exp });
  }
  return out;
}

let cves;
if (fs.statSync(dirCVEs).isDirectory()) {
  cves = leDeJson(dirCVEs);
  console.log(`Fonte dos CVEs      : pasta de JSON do benchmark (${dirCVEs})`);
} else {
  cves = leCsv(fs.readFileSync(dirCVEs, 'utf8'))
    .map((r) => ({ cve: (r.CVE || '').trim(), explanation: (r.Explanation || '').trim() }))
    .filter((r) => r.cve && r.explanation);
  console.log(`Fonte dos CVEs      : CSV versionado (${dirCVEs})`);

  // Equivalencia CONFERIDA, nao presumida: quando o clone do benchmark esta
  // presente, os dois caminhos tem de dar a mesma explanation para os mesmos
  // CVEs. Se divergirem, o CSV deixou de representar o benchmark e o numero
  // deste controle nao vale.
  const clone = process.env.BENCHMARK_CVES
    || path.join(__dirname, '..', '..', 'ossf-cve-benchmark', 'CVEs');
  if (fs.existsSync(clone)) {
    const doJson = new Map(leDeJson(clone).map((c) => [c.cve, c.explanation]));
    const doCsv = new Map(cves.map((c) => [c.cve, c.explanation]));
    const difs = [...doCsv.keys()].filter((k) => doJson.has(k) && doJson.get(k) !== doCsv.get(k));
    const soCsv = [...doCsv.keys()].filter((k) => !doJson.has(k));
    const soJson = [...doJson.keys()].filter((k) => !doCsv.has(k));
    if (difs.length || soCsv.length || soJson.length) {
      console.error(`ERRO: CSV e clone do benchmark divergem — ${difs.length} explanation(s) diferentes, ${soCsv.length} so no CSV, ${soJson.length} so no clone.`);
      difs.slice(0, 5).forEach((k) => console.error(`  ${k}: csv=${JSON.stringify(doCsv.get(k))} json=${JSON.stringify(doJson.get(k))}`));
      process.exit(1);
    }
    console.log(`Equivalencia CSV x clone do benchmark: CONFERIDA em ${doCsv.size} CVEs`);
  } else {
    console.log('AVISO: clone do benchmark ausente; equivalencia CSV x JSON nao conferida.');
  }
}

// ---------- 3. Tres testes, do mais estrito ao mais frouxo ----------

const t1 = []; // explanation == message da regra
const t2 = []; // explanation == ultimo segmento do id
const t3 = []; // explanation contida em alguma message

const chavesMessage = [...porMessage.keys()];

for (const c of cves) {
  const k = chaveTexto(c.explanation);
  if (porMessage.has(k)) t1.push({ ...c, regra: porMessage.get(k) });
  if (porIdFinal.has(k)) t2.push({ ...c, regra: porIdFinal.get(k) });

  // Substring: so vale se a explanation tiver alguma substancia,
  // senao "Cross site scripting" casaria com meio catalogo.
  if (k.length >= 12) {
    const achou = chavesMessage.find((m) => m.includes(k));
    if (achou) t3.push({ ...c, regra: porMessage.get(achou) });
  }
}

if (!cves.length) {
  console.error(`ERRO: nenhum CVE lido de ${dirCVEs}; o controle nao vale.`);
  process.exit(2);
}

const pct = (n) => ((n / cves.length) * 100).toFixed(1) + '%';

console.log(`CVEs com explanation: ${cves.length}\n`);
console.log('--- Match contra Semgrep ---');
console.log(`  T1 igual a message da regra    : ${t1.length}  (${pct(t1.length)})`);
console.log(`  T2 igual ao final do id da regra: ${t2.length}  (${pct(t2.length)})`);
console.log(`  T3 contida em alguma message   : ${t3.length}  (${pct(t3.length)})\n`);

const uniao = new Set([...t1, ...t2, ...t3].map((x) => x.cve));
console.log(`  Uniao dos tres testes          : ${uniao.size}  (${pct(uniao.size)})\n`);

for (const [rotulo, lista] of [['T1', t1], ['T2', t2], ['T3', t3]]) {
  if (!lista.length) continue;
  console.log(`--- ${rotulo}: exemplos (ate 10) ---`);
  lista.slice(0, 10).forEach((c) => {
    console.log(`  ${c.cve}  "${c.explanation}"`);
    console.log(`     regra: ${c.regra.id}`);
  });
  console.log('');
}

// Amostra do formato das regras, para o leitor entender a assimetria.
console.log('--- Amostra de messages do Semgrep (formato, para comparacao) ---');
regras.slice(0, 5).forEach((r) => {
  console.log(`  [${r.id}]`);
  console.log(`     ${r.message.slice(0, 110)}${r.message.length > 110 ? '...' : ''}`);
});
console.log('');
