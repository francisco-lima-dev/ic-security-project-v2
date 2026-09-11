# Relatórios da campanha DAST (OWASP ZAP)

Campanha executada em **24 de julho de 2026** (campo `@generated` dos quatro
JSON, todos dessa data; ZAP 2.17.0).

## Correspondência arquivo ↔ aplicação ↔ modo

| Arquivo | Aplicação | Modo |
|---|---|---|
| `juice-shop-report.json` | OWASP Juice Shop (`http://localhost:3000`) | baseline |
| `juice-shop-report.html` | OWASP Juice Shop | baseline |
| `juice-shop-full.json` | OWASP Juice Shop | full |
| `juice-shop-full.html` | OWASP Juice Shop | full |
| `nodegoat-baseline.json` | OWASP NodeGoat (`http://localhost:4000`) | baseline |
| `nodegoat-baseline.html` | OWASP NodeGoat | baseline |
| `nodegoat-full.json` | OWASP NodeGoat | full |
| `nodegoat-full.html` | OWASP NodeGoat | full |

A aplicação sai de `site[0].@name` em cada JSON. O modo sai da contagem
abaixo.

## A contagem que estabelece o modo

Duas unidades, ambas apuradas por parser JSON:

| Arquivo | Tipos de alerta<br>(entradas em `site[].alerts[]`) | Instâncias<br>(soma de `len(site[].alerts[].instances[])`) |
|---|---:|---:|
| `juice-shop-report.json` | 10 | 41 |
| `juice-shop-full.json` | 14 | 89 |
| `nodegoat-baseline.json` | 23 | 93 |
| `nodegoat-full.json` | 29 | 109 |

O campo `site[].alerts[].count` coincide com a soma das instâncias nos quatro
arquivos.

**A correspondência é robusta à escolha de unidade.** As duas séries têm os
quatro valores distintos entre si e preservam a ordem dentro de cada
aplicação — o baseline abaixo do full nas duas —, de modo que qualquer uma
das duas discrimina os quatro arquivos e as duas concordam na atribuição.

A série citada no `CLAUDE.md` (10/14/23/29) é a de **tipos de alerta**.

Cada HTML é pareado ao JSON de mesmo nome pelo conjunto de nomes de alerta,
extraídos de `<th class="risk-N">`: os conjuntos são idênticos nos quatro
pares, e não por semelhança de nome de arquivo.

## Não renomear

Os nomes dos arquivos são o artefato produzido pela execução, e por isso são
preservados como saíram. Em particular, **`juice-shop-report.json` é o
baseline**, apesar de o nome não dizer.
