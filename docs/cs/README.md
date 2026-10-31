# pvewarden

**Bezpečné aktualizace hostů v Proxmox VE pomocí AI agenta přes MCP.**

S pvewarden může AI agent udržovat aktuální virtuální stroje a kontejnery na Proxmoxu. Funguje
s Claude Code i s jakýmkoli jiným MCP klientem. Agent zjistí čekající aktualizace, udělá snapshot,
aktualizuje, restartuje a zkontroluje služby. Nikdy nedostane shell ani root. Volá jen několik
nástrojů a co smí, rozhoduje Proxmox a server, ne prompt.

> **Stav:** v0.1 těsně před vydáním. Otestováno na Proxmox VE 9 s hosty Debian 12/13 a Ubuntu
> 22.04/24.04/26.04, kontejnery i VM.

Podrobná dokumentace je v angličtině: [README](../../README.md), [instalace](install.md) (česky),
[připojení klientů](../clients.md), [konfigurace](../configuration.md),
[bezpečnostní model](../security.md), [řešení problémů](../troubleshooting.md).

```
Ty:     Jaké aktualizace čekají?
Agent:  ct101 (Debian 13): 4 bezpečnostní aktualizace. vm110 (Debian 13): nic nečeká.
        ct100 (Ubuntu 24.04): 12 aktualizací, z toho 3 bezpečnostní; docker-ce 29.1 → 29.2 je
        z repozitáře třetí strany, pvewarden ho jen hlásí.
Ty:     Nainstaluj bezpečnostní aktualizace.
Agent:  ct101: snapshot pvewarden_20261031_145241, 4 balíky nainstalovány, služby v pořádku,
        restart není potřeba.
        ct100: Proxmox ho právě zálohuje. Nic jsem neměnil, zkusím to po skončení zálohy.
```

## Proč je bezpečné ho agentovi dát

| Riziko | Co pvewarden dělá |
|---|---|
| Agent sáhne na hosta, na kterého nemá | Vidí jen hosty v poolu `pvewarden`. Aktualizace potřebují tag `pvewarden-update`, restarty tag `pvewarden-reboot`. Tagy nastavuješ jen ty. |
| Agent získá shell | SSH klíč v hostech je svázaný s vynuceným příkazem, který přijme jen pár pevných slov (`check`, `status`, `upgrade-security`, …). Žádný shell, žádné přesměrování portů. |
| Ukradený token otevře Proxmox | API token má roli omezenou na pool: vidí hosty, dělá snapshoty, rollback a zapíná a vypíná je. Nemůže vytvářet, mazat, překonfigurovat ani se dostat na hosta. |
| Aktualizace rozbije hosta | Napřed se automaticky udělá snapshot. Když selže, nic se neinstaluje. |
| Agent „vyřeší“ problém po svém | Rollback, mazání snapshotů a aktualizace bez snapshotu musíš potvrdit *ty* v dialogu, na který agent odpovědět nemůže (MCP elicitation). |
| Aktualizace přinese něco nečekaného | Jen oficiální repozitáře distribuce. Repozitáře třetích stran (Docker, PHP, …) a balíky v hold se hlásí, nikdy neinstalují. Žádné povýšení na nové vydání. |
| Záloha nebo přerušené spojení naruší aktualizaci | Když Proxmox hosta zamkne (např. při záloze), aktualizace počká. V hostovi běží odpojeně, takže přerušené spojení nezastaví dpkg v půlce. |
| Nikdo neví, co se stalo | Každé volání jde do audit logu se jménem klienta. Každá aktualizace má celý výstup apt. |

## Požadavky

- Proxmox VE 8 nebo 9. Instalátor spouštíš jako root na nodu.
- Hosté: Debian 12/13 nebo Ubuntu 22.04+, kontejnery LXC i VM.
  - VM potřebují běžící `qemu-guest-agent`, aby je pvewarden našel a mohl zapsat.
- MCP klient se streamable HTTP, např. Claude Code. Pro potvrzovací dialogy musí umět MCP
  elicitation, jinak se rollback a ostatní potvrzované akce odmítnou.
- Síť: počítač s agentem musí dosáhnout na kontejner pvewarden na TCP 8765. Kontejner musí
  dosáhnout na hosty přes SSH.

## Instalace

Na nodu Proxmoxu jako root:

```
curl -fsSLO https://github.com/matousfiser/pvewarden/releases/latest/download/pvewarden-setup
less pvewarden-setup        # čitelný shellový skript, stojí za to ho projít, než ho spustíš jako root
bash pvewarden-setup
```

Průvodce se zeptá na pár věcí a pak:

1. vytvoří pool, minimální roli a API token omezený na ten pool,
2. vytvoří malý kontejner s Debianem, ve kterém běží server (512 MB RAM),
3. vystaví serveru HTTPS certifikát podepsaný tvojí certifikační autoritou Proxmoxu,
4. nabídne **zapsání hostů**: v každém nainstaluje omezeného uživatele `pvewarden`, přidá ho do
   poolu a nastaví zvolené tagy,
5. na konci vypíše souhrn: MCP adresu, jednorázový token a příkaz pro tvůj počítač.

Na hostu Proxmoxu potom nic neběží. Krok za krokem: [install.md](install.md).

## Připojení agenta

Souhrn instalace obsahuje vše potřebné. `pvewarden-setup connect` ho vypíše znovu, bez tokenu. Pro
Claude Code:

1. Jednou vytvoř důvěru k certifikátu vypsaným příkazem. Ten stáhne certifikát CA, ověří jeho
   otisk a nastaví `NODE_EXTRA_CA_CERTS`.
2. Přidej server:
   ```
   claude mcp add --scope user --transport http pvewarden https://<server>:8765/mcp --header "Authorization: Bearer <token>"
   ```
3. Restartuj Claude Code a zeptej se: *„Jaké aktualizace čekají?“*

## Co se mění v hostovi

- systémový uživatel `pvewarden` s jedním SSH klíčem, platným jen z adresy serveru a jen pro vynucený
  příkaz `/usr/local/sbin/pvewarden-gate`,
- `/usr/local/sbin/pvewarden-guest` a `/etc/sudoers.d/pvewarden`, které povolí přesně pět příkazů
  jako root,
- `unattended-upgrades` a `sudo`, pokud chybí. pvewarden přes `unattended-upgrade` instaluje jen
  z oficiálních repozitářů.
- **automatické aktualizace:** pvewarden tvoje nastavení bez tvé volby nemění. Instalace
  `unattended-upgrades` na Debianu zapne denní automatické aktualizace, které pak probíhají bez
  snapshotu. Proto se při zapisování ptá: *ponechat* (výchozí), *vypnout*, nebo *zapnout*. Volba
  se zapíše do `/etc/apt/apt.conf.d/52pvewarden-auto-upgrades`. `check_updates` vždy hlásí aktuální
  stav.
- log poslední aktualizace v `/var/lib/pvewarden`.

`pvewarden-enroll --uninstall <vmid>` to všechno odstraní. `unattended-upgrades` a `sudo` nechá,
mohou je používat i jiné věci.

## Známá omezení (v0.1)

- **Pevná adresa serveru.** Server poslouchá na adrese, kterou měl kontejner při instalaci. Dej mu
  statickou IP nebo rezervaci v DHCP.
- **Mimo okno záloh.** Při záloze pvewarden počká, ale aktualizace na nodu, kde běží záloha, jsou
  pomalé. Neplánuj je na dobu záloh.
- **Žádní klienti v prohlížeči.** Požadavky s hlavičkou `Origin` se odmítají (ochrana proti DNS
  rebinding).
- **Jen Debian a Ubuntu.**
- **Jeden host na volání.** Agent prochází hosty postupně.
- **Interaktivní použití.** pvewarden nemá plánovač. Agent aktualizuje, když ho o to požádáš.

## Licence

[Apache-2.0](../../LICENSE)
