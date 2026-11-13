# fortidoc

Lokales Kommandozeilen-Tool, das ein unverschlüsseltes FortiGate-Backup
(FortiOS-CLI-Format, `.conf`) einliest und daraus eine Dokumentation erzeugt.

Stand: **Stufe 4 (regelwerk.xlsx und report.html)**.

## Installation

```
pip install .
```

Python 3.11 oder neuer, keine Systempakete nötig.

## Nutzung

```
fortidoc --input backup.conf --output ./doku/   # schreibt regelwerk.xlsx und report.html
fortidoc parse backup.conf          # Zusammenfassung
fortidoc parse backup.conf --json   # generischer Konfigurationsbaum als JSON
fortidoc resolve backup.conf        # aufgelöstes Regelwerk (Text)
fortidoc resolve backup.conf --json # aufgelöstes Modell als JSON
```

`parse --json` enthält alle Werte des Backups außer den Geheimnissen. `resolve`
übernimmt nur Werte aus den ausgewerteten Abschnitten; alle anderen Abschnitte
und unbekannten Schlüssel werden nur gezählt („Nicht verarbeitet“).

`regelwerk.xlsx` hat acht Reiter: Übersicht, Policies, Adressen, Dienste, NAT,
Interfaces, Auffälligkeiten und Nicht verarbeitet. Die Übersicht nennt SHA-256 der
Eingabedatei, FortiOS-Version, Tool-Version und Erstellzeit. Gleiche Eingabe ergibt
bis auf die Erstellzeit dieselbe Datei. Texte aus dem Backup werden immer als Text
geschrieben, nie als Formel.

Auffälligkeiten: deaktivierte Regeln, ACCEPT mit all/ALL (geprüft am aufgelösten
Wert), Adressen ohne subnet, ACCEPT ohne Logging, unbenutzte Objekte und unbenutzte
Werksobjekte (werkseitig angelegte Objekte wie `AFS3`, `QUAKE`, `gmail.com`). Die
Übersicht zählt die Treffer je Prüfung.

## report.html

Eine einzelne Datei, die per Doppelklick im Browser funktioniert (Chrome, Firefox,
Edge), ohne Server und ohne Internet. CSS, JavaScript und Daten sind eingebettet;
eine Content-Security-Policy verbietet jedes Nachladen. Report und Arbeitsmappe
entstehen in einem Lauf aus demselben Modell und denselben Auffälligkeiten.

Ansichten: Übersicht, Zonen-Matrix, Regeln, Adressen, Dienste, Interfaces und Zonen,
NAT, Auffälligkeiten, Nicht verarbeitet. Tabellen zeigen Seiten zu 50 bis 500 Zeilen;
Filter und Suche arbeiten auf den Daten, nicht auf dem DOM.

- **Zonen-Matrix:** Zeilen Quellzonen, Spalten Zielzonen, je VDOM. Eine Regel mit
  mehreren Zonen zählt in jeder Kombination. Gezählt werden aktive Regeln (Accept,
  Deny, Sonstige), deaktivierte stehen grau in Klammern daneben. `any` ist eine
  eigene Zeile und Spalte, das implizite Deny fehlt. Klick auf eine Zelle listet
  ihre Regeln.
- **Filter:** VDOM, Quell- und Zielzone (genauer Vergleich, `any` ist ein eigener
  Wert), Action, Status und Freitext.
- **Suche:** IP-Adresse oder Netz (IPv4/IPv6) als Quelle, Ziel oder beides, dazu
  Port mit Protokoll. *Sicher* ist ein Treffer, wenn die IP bzw. das ganze gesuchte
  Netz in einem aufgelösten Netz oder Bereich liegt und der Port in einem
  aufgelösten Dienst. Unter *möglicherweise* stehen getrennt, mit Grund: Regeln mit
  FQDN, Geo, Internet Service, dynamischen oder nicht auflösbaren Adressen, mit
  Objekten ohne subnet, mit Negation auf der gesuchten Seite, mit nur teilweise
  überlappendem Netz, mit negiertem Dienst oder Dienst mit festen Quellports. Die
  Suche wertet nur das Regelwerk aus, kein Routing.
- **Druck:** „Drucken → PDF“ ergibt A4 quer mit Deckblatt und das vollständige
  Dokument (alle Regeln und Tabellen, unabhängig von Filtern und Seiten).

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
