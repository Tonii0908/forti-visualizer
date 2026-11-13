# Annahmen zu FortiOS-Verhalten

Hier stehen alle Stellen, an denen fortidoc ein Verhalten von FortiOS annimmt,
das nicht durch eine echte Konfiguration oder Dokumentation abgesichert ist.
Im Code sind diese Stellen mit `ASSUMPTION(<Kennung>)` markiert.
Bitte bei Gelegenheit gegen echte Backups prüfen und hier abhaken.

Stand: Stufe 1 (Parser)

## Tokenizer

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| T1 | Nur das doppelte Anführungszeichen `"` leitet einen String ein. Ausnahme (Vorgabe Toni): Ein Token, das genau aus `''` besteht, ist ein leerer String (`set image-base64 ''`). Sonst ist `'` normales Zeichen. | Werte mit `'…'` würden an Leerzeichen getrennt. |
| T2 | Escapes sind `\"`, `\'` und `\\`. `\'` ist laut Toni die Maskierung des Apostrophs, **noch nicht durch ein echtes Backup bestätigt**. Jeder andere Backslash bleibt wörtlich stehen (`\n` bleibt `\n`). | Replacement Messages mit anderen Escapes würden anders dargestellt. |
| T3 | Dieselben Escapes gelten auch außerhalb von Anführungszeichen. | Ein Backslash vor `"` außerhalb eines Strings würde anders gelesen. |
| T4 | Teile ohne Leerzeichen dazwischen bilden ein Token: `ab"c d"e` ergibt `abc de`. | Nur in ungewöhnlichen Backups relevant. |
| T5 | Eine Zeile, deren erstes Zeichen außerhalb eines Strings `#` ist, ist ein Kommentar bzw. eine Kopfzeile. `#` mitten in einem Wert ist normaler Text. | – |
| T6 | Trennzeichen sind Leerzeichen und Tabulator. Zeilenenden `\r\n` werden zu `\n`, auch innerhalb mehrzeiliger Strings. | Werte mit `\r` im Original verlieren das `\r`. |

## Grammatik

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| P1 | Backups enthalten nur `config`, `edit`, `set`, `unset`, `next`, `end`. Andere Befehle (`append`, `select`, `unselect`, `clear`, `purge`, `rename`, `move` …) gelten als Syntaxfehler. | Ein Backup mit einem solchen Befehl bricht ab, statt eingelesen zu werden. |
| P2 | `end` bei offenem `edit` schließt das `edit` und den umgebenden `config`-Block. | – (so in der Aufgabenstellung beschrieben) |
| P3 | `edit` hat genau einen Namen bzw. eine ID. | Ein `edit` mit mehreren Argumenten bricht ab. |
| P4 | Ein Schlüssel kann im selben Block mehrfach vorkommen. Der Parser behält alle Vorkommen in Dateireihenfolge, die Bewertung (vermutlich „letzter gewinnt“) folgt erst in Stufe 2. | – |
| P5 | `config` darf direkt in `config` stehen (ohne `edit`). Wird generisch akzeptiert. | – |
| P6 | Ein beim Dateiende offener Block ist ein Fehler (abgeschnittene Datei). | Ein Backup ohne abschließendes `end` bricht ab. |

## Kopfzeile

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| H1 | Erste Zeile: `#config-version=<Modell>-<Version>-<Typ>-build<Nummer>-<JJMMTT>:opmode=…:vdom=…:user=…`. Die Version ist dreiteilig (`7.2.5`) oder bei FortiOS 5.x zweiteilig (`5.06`, laut Toni). Das Modell darf Bindestriche enthalten. | Modell/Version bleiben leer, es gibt einen Hinweis, kein Abbruch. |
| H2 | `vdom=0` bedeutet ohne VDOMs, `vdom=1` mit VDOMs. Maßgeblich ist aber die Struktur der Datei, bei Widerspruch gibt es einen Hinweis. Wie Split-VDOM (FortiOS 7.x) in der Kopfzeile erscheint, ist ungeprüft. | Nur der Hinweis wäre falsch, die Zuordnung folgt der Struktur. |
| H4 | Für Vergleiche wird `5.06` als Version 5.6 gelesen (`(5, 6)`), `7.2.5` als `(7, 2, 5)`. | Versionsabhängige Regeln (z. B. policy6 vor 6.4) würden falsch greifen. |
| H3 | Weitere Kopfzeilen der Form `#schlüssel=wert` (`conf_file_ver`, `buildno`, `global_vdom`) werden unverändert übernommen und nicht ausgewertet. | – |

## VDOM

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| V1 | Ein Multi-VDOM-Backup hat auf oberster Ebene `config vdom` und/oder `config global`. Die Deklaration ist ein `edit <vdom>` ohne Inhalt, danach folgt je VDOM ein `config vdom` / `edit <vdom>`-Block mit Inhalt. Mehrere Blöcke desselben VDOMs werden in Dateireihenfolge zusammengeführt. | – |
| V2 | Ohne VDOMs gehören alle Abschnitte zum VDOM `root`. Der Parser trennt dabei nicht zwischen globalen und VDOM-Abschnitten, weil er keine Abschnittsnamen kennt. Ob z. B. `system interface` dann global ist, entscheidet Stufe 2. | – |
| V3 | Andere Abschnitte auf oberster Ebene eines Multi-VDOM-Backups werden nicht verworfen, sondern unter `outside_sections` mit Hinweis geführt. | – |

## Eingabedatei

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| E1 | Verschlüsselte Backups erkennt das Tool an NUL-Bytes oder an mehr als 1 % Steuerzeichen. Das genaue Format verschlüsselter Backups ist nicht geprüft, die Fixture ist synthetisch. Eine Datei, die weder mit `#` noch mit `config` beginnt, wird ebenfalls abgelehnt. | Ein verschlüsseltes Backup mit reinem Text-Inhalt (z. B. Base64) würde mit „Keine FortiOS-Konfiguration erkannt“ abgelehnt statt mit dem Hinweis auf Verschlüsselung. |
| E2 | Backups sind UTF-8, optional mit BOM. Bei ungültigem UTF-8 wird die ganze Datei ersatzweise als Latin-1 gelesen, mit Warnung und Zeilennummer (Vorgabe Toni). | Ist die Datei in Wahrheit Windows-1252 oder gemischt, erscheinen einzelne Sonderzeichen falsch. |
| E3 | Verschlüsselte Backups beginnen mit `#FGBK` (laut Toni, **nicht an einem echten Backup geprüft**). Daran erkennt fortidoc sie zusätzlich zu E1. | Ohne die Kennung greift nur die Heuristik aus E1. |

## Geheimnisse

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| S1 | Geheim sind: jeder Wert, der mit `ENC` beginnt; jeder Wert mit `-----BEGIN`; alle Schlüssel, deren Name `password`, `passwd`, `passphrase`, `psk`, `secret`, `private-key`, `privkey`, `keytab` oder `pwd` enthält; alle Schlüssel mit einem Namensteil, der auf `key` oder `keys` endet (`key`, `authkey`, `md5-keys`, `key-string`). Die Werte werden beim Einlesen durch `***entfernt***` ersetzt, der Schlüssel bleibt sichtbar. | Zu viel geschwärzt: harmlose Werte wie ein fiktives `some-key` fehlen in der Doku. Zu wenig geschwärzt wäre ein Leck, deshalb sind die Regeln bewusst breit. |
| S3 | Zusätzlich zu den Namensregeln gibt es Pfad-Regeln: `set name` unter `config system snmp community` ist der Community-String im Klartext und wird geschwärzt (Vorgabe Toni). Der Pfad wird ohne `config global`/`config vdom` verglichen und muss genau passen. | Weitere Klartext-Geheimnisse an anderer Stelle wären nur über neue Pfad-Regeln abgedeckt. |
| S2 | Fehlermeldungen zeigen die betroffene Zeile nur geschwärzt und gekürzt. Bei einem unbekannten Befehl erscheint der Befehl selbst (max. 40 Zeichen). Ein Geheimnis, das ohne Schlüssel und ohne `ENC` als eigene Zeile im Backup stünde, ließe sich nicht erkennen. | – |
