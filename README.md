# fortidoc

Lokales Kommandozeilen-Tool, das ein unverschlüsseltes FortiGate-Backup
(FortiOS-CLI-Format, `.conf`) einliest und daraus eine Dokumentation erzeugt.

Stand: **Stufe 3 (regelwerk.xlsx)**. Der HTML-Bericht folgt in Stufe 4.

## Installation

```
pip install .
```

Python 3.11 oder neuer, keine Systempakete nötig.

## Nutzung

```
fortidoc --input backup.conf --output ./doku/   # schreibt ./doku/regelwerk.xlsx
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
Wert), Adressen ohne subnet, ACCEPT ohne Logging und unbenutzte Objekte.

Geheimnisse (Passwort-Hashes, Pre-Shared Keys, private Schlüssel, Zertifikate)
werden schon beim Einlesen entfernt und erscheinen in keiner Ausgabe.

## Tests

```
pip install -e ".[test]"
pytest
```

Offene Annahmen zu FortiOS-Verhalten stehen in [ANNAHMEN.md](ANNAHMEN.md).
