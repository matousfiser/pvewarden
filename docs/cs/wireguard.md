# Přístup k serveru přes WireGuard

Pro případ, kdy agenti nejsou v LAN Proxmoxu, ale dostávají se k ní přes WireGuard VPN, a server má
být vidět jen ve VPN.

## Dvě adresy

Kontejner se serverem má pak dvě adresy:

| Adresa | Příklad | K čemu |
|---|---|---|
| LAN (`eth0`) | `10.100.0.200` | Z ní se server připojuje k hostům přes SSH. Hosté server přijmou jen z této adresy (`from=` v `authorized_keys`). |
| VPN (`wg0`) | `10.200.0.200` | Jen na ní server poslouchá (port 8765). Připojují se na ni agenti. |

Hosté nemusí být ve VPN a agenti nemusí vidět do LAN.

## V průvodci

1. **Síť:** LAN adresa kontejneru, např. `10.100.0.200/24`, a brána LAN.
2. **Jak se agenti připojí:** *Through a VPN inside the container*.
3. **Adresa kontejneru ve VPN:** např. `10.200.0.200`.
4. **HTTPS i na téhle adrese?** Stačí *No*. WireGuard končí přímo v kontejneru, takže provoz je
   šifrovaný celou cestu od agenta až k serveru.

Adresa v kontejneru zatím neexistuje, proto průvodce na konci napíše
„pvewarden is installed; it starts once 10.200.0.200 exists“. To je v pořádku. **Token agenta si
ulož:** ukáže se jen jednou.

## WireGuard v kontejneru

**1. Peer na WireGuard serveru** s VPN adresou kontejneru jako `/32` (např. `10.200.0.200/32`).
Stáhni si jeho klientský config. Řada webových správců WireGuardu při změně jen přepíše soubor,
takže na WireGuard serveru načti změnu i do běžícího rozhraní (`wg syncconf wg0 <(wg-quick strip wg0)`,
jako root).

**2. Modul jádra na Proxmox hostu.** Neprivilegovaný kontejner si ho nenačte sám, proto ho načti
na hostu, teď i po každém startu (jako root):

```
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf
```

**3. Klient v kontejneru.** Na Proxmox hostu jako root (`103` je ID kontejneru):

```
pct enter 103
apt-get update && apt-get install -y wireguard-tools
nano /etc/wireguard/wg0.conf        # vlož klientský config
chmod 600 /etc/wireguard/wg0.conf
```

Před spuštěním uprav v configu dva řádky:

- **Smaž řádek `DNS = ...`.** Kontejner nemá `resolvconf` a `wg-quick` by spadl.
- **`AllowedIPs` jen na síť VPN**, např. `AllowedIPs = 10.200.0.0/24`. Výchozí `0.0.0.0/0` by
  poslal do VPN veškerý provoz a odřízl kontejner od hostů.

Pak:

```
systemctl enable --now wg-quick@wg0
wg show                              # "latest handshake: ... seconds ago"
exit
```

**4. Kontrola.** Jakmile adresa existuje, server do 10 sekund naběhne sám a po restartu startuje až
po `wg-quick@wg0`. Na Proxmox hostu:

```
pvewarden-setup doctor
```

Řádek `HTTP` ukáže `http://10.200.0.200:8765/mcp`. Na tu adresu připoj agenty
(`pvewarden-setup connect` ukáže jak).

## Když to nejde

- **`wg-quick` hlásí `Unknown device type`:** na hostu není načtený modul (krok 2).
- **`resolvconf: command not found`:** v configu zůstal řádek `DNS =`.
- **Žádný handshake:** peer ještě není aktivní na WireGuard serveru (načti ho tam), nebo je
  blokované UDP k WireGuard serveru.
- **doctor varuje „Listen address ... is not an address of this machine“:** `wg0` neběží, nebo má
  jinou adresu, než jaká byla zadaná v průvodci. Porovnej `ip -o addr show` v kontejneru s `listen`
  v `/etc/pvewarden/config.toml`.
