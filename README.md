# fortidoc

Lokales Kommandozeilen-Tool, das ein unverschlüsseltes FortiGate-Backup
(FortiOS-CLI-Format, `.conf`) einliest und daraus eine Dokumentation erzeugt.

Stand: **Stufe 2 (Datenmodell und Resolver)**. Excel- und HTML-Ausgabe folgen in Stufe 3 und 4.

## Installation

```
pip install .
```

Python 3.11 oder neuer, keine Systempakete nötig.

## Nutzung

```
fortidoc parse backup.conf          # Zusammenfassung
fortidoc parse backup.conf --json   # generischer Konfigurationsbaum als JSON
fortidoc resolve backup.conf        # aufgelöstes Regelwerk (Text)
fortidoc resolve backup.conf --json # aufgelöstes Modell als JSON
```

`parse --json` enthält alle Werte des Backups außer den Geheimnissen. `resolve`
übernimmt nur Werte aus den ausgewerteten Abschnitten; alle anderen Abschnitte
und unbekannten Schlüssel werden nur gezählt („Nicht verarbeitet“).

Geheimnisse (Passwort-Hashes, Pre-Shared Keys, private Schlüssel, Zertifikate)
werden schon beim Einlesen entfernt und erscheinen in keiner Ausgabe.

## Tests

```
pip install -e ".[test]"
pytest
```

Offene Annahmen zu FortiOS-Verhalten stehen in [ANNAHMEN.md](ANNAHMEN.md).
