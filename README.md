# fortidoc

Lokales Kommandozeilen-Tool, das ein unverschlüsseltes FortiGate-Backup
(FortiOS-CLI-Format, `.conf`) einliest und daraus eine Dokumentation erzeugt.

Stand: **Stufe 5 (regelwerk.xlsx, report.html, regelwerk.md)**.

## Installation

```
pip install .
```

Python 3.11 oder neuer, keine Systempakete nötig.

## Nutzung

```
fortidoc --input backup.conf --output ./doku/   # schreibt regelwerk.xlsx, report.html und regelwerk.md
fortidoc parse backup.conf          # Zusammenfassung
fortidoc parse backup.conf --json   # generischer Konfigurationsbaum als JSON
fortidoc resolve backup.conf        # aufgelöstes Regelwerk (Text)
fortidoc resolve backup.conf --json # aufgelöstes Modell als JSON
```

`parse --json` enthält alle Werte des Backups außer den Geheimnissen. `resolve`
übernimmt nur Werte aus den ausgewerteten Abschnitten; alle anderen Abschnitte
und unbekannten Schlüssel werden nur gezählt („Nicht verarbeitet“).

Ausgewertet werden `firewall policy`, `policy6`, `security-policy` (NGFW-Modus
richtlinienbasiert, mit Anwendungen und Kategorien) sowie `local-in-policy` und
`local-in-policy6`. Local-In-Regeln bilden eine eigene Tabelle; ihr Ziel ist die
FortiGate selbst. Im NGFW-Modus richtlinienbasiert (`ngfw-mode policy-based`) ist
das Regelwerk die Liste der Security-Policies; die Einträge in `firewall policy`
steuern dann SSL-Inspection und Authentifizierung und stehen in einer eigenen
Tabelle (nicht in Matrix, Diagramm und Suche). Die Übersicht nennt den Modus.

`regelwerk.xlsx` hat zehn Reiter: Übersicht, Policies, Local-In, SSL-Inspection,
Adressen, Dienste, NAT, Interfaces, Auffälligkeiten und Nicht verarbeitet. Die Übersicht nennt SHA-256 der
Eingabedatei, FortiOS-Version, Tool-Version und Erstellzeit. Gleiche Eingabe ergibt
bis auf die Erstellzeit dieselbe Datei. Texte aus dem Backup werden immer als Text
geschrieben, nie als Formel.

Auffälligkeiten: deaktivierte Regeln, ACCEPT mit all/ALL (geprüft am aufgelösten
Wert), Adressen ohne subnet, ACCEPT ohne Logging, überdeckte Regeln, unbenutzte
Objekte und unbenutzte Werksobjekte (werkseitig angelegte Objekte wie `AFS3`,
`QUAKE`, `gmail.com`). Die Übersicht zählt die Treffer je Prüfung.

**Überdeckte Regeln:** Eine Regel greift nie, wenn eine frühere aktive Regel
derselben Tabelle alle ihre Zonen, Adressen und Dienste umfasst. fortidoc meldet
nur, was es beweisen kann: Regeln mit FQDN, Geo, dynamischen Adressen, VIPs,
Internet Service oder Negation werden nicht als überdeckt gemeldet, und eine
frühere Regel zählt nur mit ihren exakten Werten. Eine frühere Regel mit
einschränkenden Bedingungen (FSSO-Gruppen, Geräte, ZTNA-Tags, ToS u. a.) überdeckt
nie. Der Befund nennt die frühere
Regel und ob sie eine andere Action hat (Details: ANNAHMEN.md, U1–U6).

## report.html

Eine einzelne Datei, die per Doppelklick im Browser funktioniert (Chrome, Firefox,
Edge), ohne Server und ohne Internet. CSS, JavaScript und Daten sind eingebettet;
eine Content-Security-Policy verbietet jedes Nachladen. Report und Arbeitsmappe
entstehen in einem Lauf aus demselben Modell und denselben Auffälligkeiten.

Ansichten: Übersicht, Zonen-Matrix, Zonen-Diagramm, Regeln, Local-In,
SSL-Inspection (nur im NGFW-Modus richtlinienbasiert), Adressen, Dienste,
Interfaces und Zonen, NAT, Auffälligkeiten, Nicht verarbeitet. Tabellen
zeigen Seiten zu 50 bis 500 Zeilen; Filter und Suche arbeiten auf den Daten, nicht
auf dem DOM.

- **Zonen-Matrix:** Zeilen Quellzonen, Spalten Zielzonen, je VDOM. Eine Regel mit
  mehreren Zonen zählt in jeder Kombination. Gezählt werden aktive Regeln (Accept,
  Deny, Sonstige), deaktivierte stehen grau in Klammern daneben. `any` ist eine
  eigene Zeile und Spalte, das implizite Deny fehlt. Klick auf eine Zelle listet
  ihre Regeln.
- **Zonen-Diagramm:** dieselben Daten als Bild (eingebettetes SVG): links
  Quellzonen, rechts Zielzonen, eine Linie je Zonen-Kombination und Action, die
  Linienstärke wächst mit der Zahl der Regeln. Erscheint auch im Druck.
- **Filter:** VDOM, Quell- und Zielzone (genauer Vergleich, `any` ist ein eigener
  Wert), Action, Status und Freitext.
- **Suche:** IP-Adresse oder Netz (IPv4/IPv6) als Quelle, Ziel oder beides, dazu
  Port mit Protokoll. *Sicher* ist ein Treffer, wenn die IP bzw. das ganze gesuchte
  Netz in einem aufgelösten Netz oder Bereich liegt und der Port in einem
  aufgelösten Dienst. Unter *möglicherweise* stehen getrennt, mit Grund: Regeln mit
  FQDN, Geo, Internet Service, dynamischen oder nicht auflösbaren Adressen, mit
  Objekten ohne subnet, mit Negation auf der gesuchten Seite, mit nur teilweise
  überlappendem Netz, mit negiertem Dienst oder Dienst mit festen Quellports, und
  Security-Policies mit Anwendung oder Kategorie. Die Suche wertet nur das
  Regelwerk aus, kein Routing.
- **Druck:** „Drucken → PDF“ ergibt A4 quer mit Deckblatt und das vollständige
  Dokument (alle Regeln und Tabellen, unabhängig von Filtern und Seiten).

## regelwerk.md

Markdown für Wikis und Git-Repositories (GitHub, GitLab, Azure DevOps rendern
Mermaid): Übersicht, je VDOM ein Mermaid-Zonendiagramm und die Zonen-Matrix als
Tabelle, Regeln, Local-In-Regeln und Auffälligkeiten. Lange Wertelisten sind nach
zehn Einträgen gekürzt, die vollständigen Listen stehen in der Arbeitsmappe. Über
500 Zonen-Kombinationen (Grenze von Mermaid) steht statt des Diagramms ein Hinweis.
Sonderzeichen in Zonennamen erscheinen im Diagramm als `?`, die Tabellen zeigen die
genauen Namen.

Geheimnisse (Passwort-Hashes, Pre-Shared Keys, private Schlüssel, Zertifikate)
werden schon beim Einlesen entfernt und erscheinen in keiner Ausgabe.

## Tests

```
pip install -e ".[test]"
pytest
```

Die Browser-Tests (`tests/test_report_browser.py`) laufen nur, wenn Playwright mit
Chromium installiert ist (`pip install playwright && playwright install chromium`),
sonst werden sie übersprungen. Der Lasttest mit einem synthetischen 8-MB-Backup
läuft zusätzlich nur mit `FORTIDOC_PERF=1`.

Offene Annahmen zu FortiOS-Verhalten stehen in [ANNAHMEN.md](ANNAHMEN.md).
