# Přístup k serveru přes VPN

Pro případ, kdy agenti nejsou v LAN Proxmoxu, ale dostávají se k ní přes VPN, a server má být vidět
jen ve VPN. Hodí se jakákoli VPN, která dá kontejneru se serverem vlastní adresu: klient VPN běží
přímo v kontejneru.

## Dvě adresy

Kontejner se serverem má pak dvě adresy:

| Adresa | Příklad | K čemu |
|---|---|---|
| LAN (`eth0`) | `10.100.0.200` | Z ní se server připojuje k hostům přes SSH. Hosté server přijmou jen z této adresy (`from=` v `authorized_keys`). |
| VPN | `10.200.0.200` | Jen na ní server poslouchá (port 8765). Připojují se na ni agenti. |

Hosté nemusí být ve VPN a agenti nemusí vidět do LAN.

## V průvodci

1. **Síť:** LAN adresa kontejneru, např. `10.100.0.200/24`, a brána LAN.
2. **Jak se agenti připojí:** *Through a VPN inside the container*.
3. **Adresa kontejneru ve VPN:** např. `10.200.0.200`.
4. **HTTPS i na téhle adrese?** *Yes* (výchozí). Někteří MCP klienti vzdálený server přes HTTP
   odmítnou bez ohledu na síť. S *No* jde HTTPS zapnout později: `pvewarden-setup renew-cert`.

Adresa v kontejneru zatím neexistuje, proto průvodce na konci napíše
„pvewarden is installed; it starts once 10.200.0.200 exists“. To je v pořádku. **Token agenta si
ulož:** ukáže se jen jednou.

## VPN v kontejneru

Nainstaluj a nastav v kontejneru klienta své VPN (`pct enter <ctid>` na Proxmox hostu) tak, aby měl
adresu zadanou v průvodci a startoval po spuštění. U každé VPN platí tři věci:

- **Do VPN směruj jen síť VPN.** Klient, který pošle do VPN veškerý provoz (výchozí trasa,
  `0.0.0.0/0`), odřízne kontejner od hostů v LAN.
- **Ať klient VPN nemění DNS**, pokud to kontejner neumí použít. Šablona Debianu nemá
  `resolvconf` a některým klientům bez něj start selže.
- **Neprivilegovaný kontejner si sám nenačte modul jádra ani nevytvoří TUN zařízení.** VPN, která
  potřebuje modul jádra (např. WireGuard), ho potřebuje načtený na Proxmox hostu. VPN, která
  potřebuje `/dev/net/tun` (OpenVPN, Tailscale a další), potřebuje zařízení předané do kontejneru
  (Proxmox UI: kontejner -> Resources -> Add -> Device Passthrough, `/dev/net/tun`).

Příklad s WireGuardem, jako root:

```
# na Proxmox hostu: modul jádra, teď i po každém startu
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf

# v kontejneru
pct enter <ctid>
apt-get update && apt-get install -y wireguard-tools
nano /etc/wireguard/wg0.conf        # config peeru z tvého WireGuard serveru
chmod 600 /etc/wireguard/wg0.conf   # bez řádku DNS =; AllowedIPs = jen síť VPN
systemctl enable --now wg-quick@wg0
exit
```

## Kontrola

Jakmile adresa existuje, server do 10 sekund naběhne sám a po restartu to zkouší znovu, dokud VPN
neběží. Na Proxmox hostu:

```
pvewarden-setup doctor
```

Řádek `HTTP` ukáže `https://10.200.0.200:8765/mcp`. Na tu adresu připoj agenty
(`pvewarden-setup connect` ukáže jak, včetně jednorázové důvěry v Proxmox CA).

**Instalace s HTTP** (`http://...`): `pvewarden-setup renew-cert` ji přepne na HTTPS na stejné
adrese. Tokeny zůstanou; agenti změní adresu na `https://` a začnou důvěřovat Proxmox CA.

## Když to nejde

- **doctor varuje „Listen address ... is not an address of this machine“:** VPN v kontejneru
  neběží, nebo má jinou adresu, než jaká byla zadaná v průvodci. Porovnej `ip -o addr show`
  v kontejneru s `listen` v `/etc/pvewarden/config.toml`.
- **VPN běží, ale agenti nedostanou odpověď:** ověř, že VPN pustí adresu agenta na VPN adresu
  kontejneru, TCP port 8765, a že agent používá `https://`, když má server certifikát.
