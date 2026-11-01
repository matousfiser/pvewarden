# Instalace, aktualizace, odstranění

Všechno dělá jeden skript, `pvewarden-setup`. Spouští se jako root na nodu Proxmox VE. Bez argumentů
ukáže menu, s příkazem jde rovnou na věc:

| Příkaz | Co dělá |
|---|---|
| `install` | Nastaví přístup k Proxmoxu, vytvoří kontejner se serverem a zapíše hosty |
| `enroll` | Přidá hosty (nebo změní, co na nich agenti smějí) |
| `connect` | Znovu ukáže, jak připojit agenta (bez tokenu) |
| `token [jméno]` | Dá agentovi nový token; starý okamžitě přestane platit |
| `renew-cert` | Nový HTTPS certifikát, např. po změně adresy serveru |
| `upgrade` | Aktualizuje server a nástroje na hostu na verzi tohoto skriptu |
| `uninstall` | Odstraní pvewarden z hostů, z Proxmoxu i z tohoto nodu |

Volby: `--dry-run` jen ukáže, co by se stalo. `--yes` vezme výchozí odpovědi nebo proměnné
`PVEWARDEN_*` (viz [anglický návod](../install.md#unattended-install)). `--source DIR|TARBALL`
nainstaluje lokální kopii místo stažení vydání.

## Než začneš

- **Proxmox VE 8 nebo 9.** V clusteru spusť skript na jednom nodu, kontejner bude tam.
- **Pevná adresa serveru.** Agenti se k ní připojují a certifikát je vystavený na ni. V průvodci
  zadej statickou IP, nebo adresu zarezervuj v DHCP.
- **Hosté:** Debian 12/13 nebo Ubuntu 22.04 a novější, zapnutí a s přístupem k zrcadlům balíků. VM
  potřebují nainstalovaný `qemu-guest-agent` a zapnutou volbu *QEMU Guest Agent* v Proxmoxu.
- **Úložiště:** před aktualizací se dělá snapshot, takže disky hostů musí být na úložišti se
  snapshoty (ZFS, LVM-thin, Ceph RBD, soubory qcow2). Na obyčejném LVM nebo raw souborech snapshot
  selže a aktualizace se odmítne.

## Instalace

```
curl -fsSLO https://github.com/matousfiser/pvewarden/releases/latest/download/pvewarden-setup
less pvewarden-setup
bash pvewarden-setup install
```

Otázky v pořadí:

1. **Kontejner.** *Výchozí* je Debian, 1 jádro, 512 MB RAM, 4 GB disk, další volné ID a první bridge.
   *Pokročilé* dovolí nastavit ID, hostname, úložiště, velikost, bridge a VLAN.
2. **Síť.** IPv4 adresa s prefixem (např. `192.168.1.50/24`) a brána, nebo `dhcp`. Volitelně IPv6,
   DNS servery a doména. Prázdné znamená stejné jako na hostu.
3. **Heslo roota** v kontejneru. Prázdné znamená bez hesla, `pct enter` funguje vždy.
4. **SSH klíče** pro roota v kontejneru: z účtu na GitHubu nebo GitLabu (veřejné klíče
   z `github.com/<uživatel>.keys`), vložené, ze souboru, z URL, nebo žádné. Průvodce ukáže otisky
   přidaných klíčů, abys je porovnal se svými.
5. **Jak se agenti připojí.**
   - *HTTPS na adrese kontejneru* (doporučeno). Certifikát podepíše certifikační autorita tvého
     Proxmoxu a klienti jí jednou začnou důvěřovat příkazem ze souhrnu.
   - *Moje vlastní adresa*, např. WireGuard IP, kterou si v kontejneru nastavíš sám. Tady jde zvolit
     i HTTP bez šifrování, což uvnitř VPN stačí.
6. **Jméno prvního agenta.** Objevuje se v audit logu a v popisech snapshotů.
7. **Kontrola.** Průvodce vypíše, co vytvoří. Dokud nepotvrdíš, nic se neděje.

Pak průvodce:

- vytvoří v Proxmoxu pool `pvewarden`, roli `Warden`, uživatele `pvewarden@pve` bez přihlášení a jeho
  token. Token platí jen na pool a jde rovnou do konfigurace serveru, nikde se nevypisuje.
- vytvoří kontejner (neprivilegovaný, startuje s nodem) a nainstaluje do něj server,
- vystaví HTTPS certifikát. Privátní klíč vznikne v kontejneru a nikdy ho neopustí.
- nainstaluje na hosta `pvewarden-enroll` a zeptá se, jestli **zapsat hosty** hned,
- spustí server, provede kontrolu (`pvewarden doctor`) a vypíše souhrn.

V souhrnu je MCP adresa, token agenta a příkazy pro připojení. **Token se ukáže jen jednou.** Když ho
ztratíš, `pvewarden-setup token` vytvoří nový. Připojení klientů: [clients.md](../clients.md).

## Zapsání hostů

`pvewarden-setup enroll` (nebo otázka na konci instalace) ukáže seznam hostů k zaškrtnutí a pak se
zeptá:

- **Co agenti smějí:**
  - *jen číst:* bez tagů,
  - *instalovat aktualizace:* tag `pvewarden-update`,
  - *instalovat a restartovat:* tagy `pvewarden-update` a `pvewarden-reboot`.
- **Automatické aktualizace**, tedy vlastní denní unattended-upgrades hosta:
  - *ponechat* (výchozí) nechá nastavení každého hosta, jak je,
  - *vypnout* znamená, že aktualizace instaluje jen pvewarden, vždy se snapshotem,
  - *zapnout* znamená, že se hosté aktualizují i sami každý den.

Zapsání přidá hosta do poolu, doplní tagy a nainstaluje klienta. Spustit ho znovu je bezpečné, jen
obnoví klienta. Z příkazové řádky:

```
pvewarden-enroll --pool --tags pvewarden-update,pvewarden-reboot 101 102 110
pvewarden-enroll --all                  # obnoví klienta na všech hostech v poolu
pvewarden-enroll --uninstall 102        # odstraní klienta z hosta
```

**Změna oprávnění později:** uprav tagy v Proxmoxu (host → Summary → tagy). Bez `pvewarden-update`
je host pro agenty jen ke čtení. Host vyřazený z poolu `pvewarden` pro pvewarden neexistuje.

## Aktualizace pvewarden

Stáhni nový `pvewarden-setup` a spusť:

```
bash pvewarden-setup upgrade
```

Aktualizuje server v kontejneru a nástroje na hostu. Konfigurace, tokeny, klíče hostů, audit log
i certifikát zůstanou. Pak nabídne znovu zapsat všechny hosty, čímž se obnoví jejich klient.
Potvrď to, pokud nevíš jistě, že se klient nezměnil. Nastavení automatických aktualizací hostů
zůstane.

**Z verze 0.1.1 a starší:** hosté dřív sdíleli jeden SSH klíč, od 0.1.2 má každý vlastní. Nové
zapsání je převede a server do té doby hosta odmítá. Až mají vlastní klíč všichni, upgrade starý
sdílený klíč ze serveru smaže.

## Odstranění

```
bash pvewarden-setup uninstall
```

Odstraní postupně:

1. klienta ze všech hostů v poolu,
2. token, uživatele, roli a pool v Proxmoxu. Hosté zůstanou, zmizí jen jejich členství v poolu.
3. nástroje na hostu.

Tagy hostů zůstanou. Kontejner i s audit logem se smaže jen po samostatném potvrzení. Snapshoty,
které pvewarden udělal, se nemažou; případně je smaž v Proxmoxu.

Ruční instalace bez průvodce je popsaná v [anglickém návodu](../install.md#manual-install).
