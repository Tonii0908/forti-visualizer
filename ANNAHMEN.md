# Annahmen zu FortiOS-Verhalten

Hier stehen alle Stellen, an denen fortidoc ein Verhalten von FortiOS annimmt,
das nicht durch eine echte Konfiguration oder Dokumentation abgesichert ist.
Im Code sind diese Stellen mit `ASSUMPTION(<Kennung>)` markiert.
Bitte bei Gelegenheit gegen echte Backups prüfen und hier abhaken.

Stand: Stufe 2 (Datenmodell und Resolver)

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
| P4 | Ein Schlüssel kann im selben Block mehrfach vorkommen. Der Parser behält alle Vorkommen in Dateireihenfolge. Der Resolver wertet „letzter gewinnt“ aus; `unset` entfernt den Wert, danach gilt der Default. | Bei doppelten Schlüsseln würde der falsche Wert gezeigt. |
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
| V2 | Ohne VDOMs gehören alle Abschnitte zum VDOM `root`. Der Parser trennt nicht zwischen globalen und VDOM-Abschnitten. **Entschieden (Toni):** Die VDOM-Zuordnung eines Interfaces kommt aus `set vdom` am Interface, nicht aus der Position in der Datei. | – |
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

## Defaults (Stufe 2, zentral in `src/fortidoc/model/defaults.py`)

`action deny` und `status enable` bei Policies sind durch die Aufgabenstellung
vorgegeben. Alle anderen Defaults sind Annahmen.

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| D1 | Policy: `nat`, `ippool`, `srcaddr-negate`, `dstaddr-negate`, `service-negate`, `internet-service`, `internet-service-src`, `utm-status` sind ohne Eintrag `disable`. | NAT, Negation oder Internet Service würden falsch angezeigt. |
| D2 | Policy: `logtraffic` ist ohne Eintrag `utm` (nur Sicherheitsereignisse). | Die Logging-Spalte und später die Auffälligkeit „ACCEPT ohne Logging“ wären falsch. |
| D3 | Adresse: `type` ist ohne Eintrag `ipmask`, `subnet` ist `0.0.0.0 0.0.0.0` (so steht `all` im Backup). | Adressen ohne Typ würden falsch aufgelöst. |
| D4 | IPv6-Adresse: `type` ist `ipprefix`, `ip6` ist `::/0`. | wie D3 für IPv6 |
| D5 | Adressgruppe: `exclude` ist `disable`. Ist `exclude-member` gesetzt, aber `exclude` nicht aktiviert, wird der Ausschluss nicht angewendet und als Hinweis gezeigt. | Ausschlüsse würden fälschlich ignoriert. |
| D6 | Dienst: `protocol` ist `TCP/UDP/SCTP`. Bei `protocol IP` bedeutet fehlende oder `0` als `protocol-number` „alle IP-Protokolle“ (so ist `ALL` definiert). | Dienste ohne Protokoll würden falsch aufgelöst. |
| D7 | VIP: `type static-nat`, `extintf any`, `portforward disable`, `protocol tcp`. | Externe Seite der VIP falsch dargestellt. |
| D8 | IP-Pool: `type overload`. | Pool-Typ falsch angezeigt. |
| D9 | Central-SNAT: `status enable`, `nat enable`. Ohne `nat-ippool` wird auf die Adresse des Ausgangs-Interfaces übersetzt. | SNAT-Tabelle falsch. |
| D10 | `system settings`: `central-nat disable`, `opmode nat`. | Central NAT würde nicht erkannt. |
| D11 | Zone: `intrazone deny`. | Nur Anzeige. |
| D12 | Interface ohne `set vdom` gehört zu `root` (mit Hinweis am Interface). | Interface im falschen VDOM, falsche Hinweise in Regeln. |
| D13 | SD-WAN-Mitglied ohne `set zone` gehört zur Zone `virtual-wan-link`. | Interface in falscher Zone. |
| D14 | Die implizite Deny-Regel trägt die ID 0. | Nur Anzeige. |
| D15 | Die Objekte `all` und `all6` (in `firewall address` und `firewall address6`) sind auch ohne `subnet`/`ip6` im Backup `0.0.0.0/0` bzw. `::/0`. Es bekommt keinen Hinweis „kein subnet“ und gilt als „all“. | „all“-Regeln würden als „Adresse ohne subnet“ gemeldet. |

## Auflösung (Stufe 2)

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| A1 | Eine Adresse mit gesetzten Hostbits (`10.0.1.5 255.255.255.0`) steht für das ganze Netz (`10.0.1.0/24`). Das wird als Hinweis am Wert gezeigt. | Der Wert wäre zu weit gefasst. |
| A2 | Ein Interface ohne `type`, aber mit `vlanid`, ist ein VLAN. Ohne beides bleibt der Typ „nicht gesetzt“. | Typ falsch angezeigt. |
| A3 | Bei Wildcard-Adressen sind gesetzte Bits in der Maske die verglichenen Bits (wie bei einer Netzmaske, nicht invertiert wie bei Cisco). Eine zusammenhängende Maske wird als Netz gezeigt, sonst „nicht auflösbar“. | Wildcard-Netze wären falsch. |
| A4 | Objektnamen werden in dieser Reihenfolge gesucht: `firewall address`, `addrgrp`, `vip`, `vipgrp` (IPv6: `address6`, `addrgrp6`). `vip6` wird nicht ausgewertet; ein Verweis darauf erscheint als „nicht gefunden“. | Bei doppelten Namen würde das falsche Objekt genommen. |
| A5 | Bei Central NAT gibt eine Regel einen Hinweis auf eine VIP, wenn die VIP auf ein Ziel der Regel übersetzt (Überlappung mit `mappedip`) und das `extintf` der VIP zu einem Quell-Interface der Regel passt oder `any` ist. Hat die Regel das Ziel `0.0.0.0/0`, gibt es statt vieler Einzelhinweise einen einzigen Hinweis: Alle VIPs mit passendem `extintf` wirken. | Hinweise fehlen oder sind zu viel. |
| A6 | Ohne `ippool enable` übersetzt eine Policy mit `nat enable` auf die Adresse des Ausgangs-Interfaces. | NAT-Spalte falsch. |
| A7 | FortiOS 6.0/6.2: `config system virtual-wan-link` wird wie `system sdwan` ausgewertet. Die Mitglieder stehen unter `config members` (`set interface`), Regeln verweisen auf das Interface `virtual-wan-link`. Alle Mitglieder gehören zur SD-WAN-Zone `virtual-wan-link`. Gibt es bereits ein echtes Interface mit diesem Namen, bleibt es unverändert. | Zonen und Interfaces von SD-WAN-Regeln auf 6.x wären falsch. |
| A8 | Eine Adresse ohne `subnet` (IPv6: ohne `ip6`) bekommt den FortiOS-Default `0.0.0.0/0` bzw. `::/0` mit dem Hinweis „kein subnet im Backup, FortiOS-Default“. Das betrifft auch Sonderobjekte wie `FABRIC_DEVICE`, deren tatsächlicher Inhalt nur auf dem Gerät sichtbar ist. Solche Werte gelten nicht als „all“. Ausnahme sind `all` und `all6` (D15). | Sonderobjekte sähen wie „all“ aus oder wären falsch aufgelöst. |

## Excel und Auffälligkeiten (Stufe 3)

| Kennung | Annahme | Folge, wenn falsch |
|---|---|---|
| X1 | „ACCEPT mit all/ALL“ prüft aufgelöste Werte: ein Netz `0.0.0.0/0` oder `::/0`, das ausdrücklich im Backup steht, oder ein Dienst „IP alle Protokolle“ (`protocol IP`, `protocol-number 0`). Negierte Seiten („alles außer …“) zählen nicht. Deaktivierte ACCEPT-Regeln werden zusätzlich zu „Deaktivierte Regel“ geprüft. | „all“-Regeln würden übersehen oder zu viel gemeldet. |
| X2 | Werte mit dem Hinweis aus A8 erscheinen als eigene Auffälligkeit „Adresse ohne subnet“. `all` und `all6` ohne `subnet`/`ip6` erscheinen dagegen als „all“ (D15, von Toni entschieden). | Sonderobjekte würden als „all“ gemeldet oder umgekehrt. |
| X3 | „ACCEPT ohne Logging“ heißt `logtraffic disable`. `utm` (Default, D2) gilt als Logging. | Regeln, die nur Sicherheitsereignisse loggen, würden nicht gemeldet. |
| X4 | Unbenutzte Objekte: Ein Objekt gilt als benutzt, wenn sein Name als Wert irgendeines `set` im gesamten Backup vorkommt (auch in nicht ausgewerteten Abschnitten, in `config global`, außerhalb von global/vdom und im eigenen VDOM; Verweise aus anderen VDOMs zählen nicht), außer im eigenen Eintrag. Kommentarfelder (`comment`, `comments`, `description`) und geschwärzte Werte zählen nicht. Geprüft werden Adressen, Adressgruppen (IPv4/IPv6), VIPs, VIP-Gruppen, IP-Pools, Dienste und Dienstgruppen. Vordefinierte Objekte (z. B. `FABRIC_DEVICE`, `ALL_TCP`) werden genauso geprüft. | Objekte würden fälschlich als unbenutzt oder benutzt gemeldet. |
| X5 | Bei Central NAT wirken VIPs ohne Verweis in einer Regel. Sie werden daher nie als unbenutzt gemeldet. | VIPs würden fälschlich als unbenutzt gemeldet. |
| X6 | Excel: Alle Texte aus dem Backup werden als Text geschrieben, nie als Formel. Zeichen, die XLSX nicht erlaubt (Steuerzeichen außer Tab und Zeilenumbruch), werden entfernt. Listen, die eine Zelle (32.767 Zeichen) sprengen würden, enden mit „… und N weitere“ und verweisen auf den Reiter Adressen bzw. Dienste; andere zu lange Texte enden mit „… (gekürzt)“. | Nur Darstellung. |
