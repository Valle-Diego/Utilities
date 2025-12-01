from flask import Flask, render_template, request
import ipaddress
import math

app = Flask(__name__)

# -------------------- Funzioni numeriche --------------------
def converti_numero(valore, base):
    try:
        if base == "dec": 
            n = int(valore)
        elif base == "bin": 
            n = int(valore, 2)
        elif base == "oct": 
            n = int(valore, 8)
        elif base == "hex": 
            n = int(valore, 16)
        else:
            return None
        
        return {
            "dec": str(n),
            "bin": bin(n)[2:],
            "oct": oct(n)[2:],
            "hex": hex(n)[2:].upper()
        }
    except:
        return None

# -------------------- Funzioni IPv4 --------------------
def ipv4_dec_to_bin(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts): return None
        return ".".join(format(p, "08b") for p in parts)
    except:
        return None

def ipv4_bin_to_dec(ip):
    try:
        parts = ip.split(".")
        if len(parts) != 4: return None
        return ".".join(str(int(p, 2)) for p in parts)
    except:
        return None

# -------------------- Funzioni IPv6 --------------------
def ipv6_hex_to_bin(ip):
    try:
        addr = ipaddress.IPv6Address(ip)
        bin_str = bin(int(addr))[2:].zfill(128)
        return ".".join(bin_str[i:i+16] for i in range(0,128,16))
    except:
        return None

def ipv6_bin_to_hex(bits):
    try:
        bits = bits.replace(".", "")
        if len(bits) != 128: return None
        dec_val = int(bits, 2)
        addr = ipaddress.IPv6Address(dec_val)
        return str(addr.compressed)
    except:
        return None

# -------------------- Classful --------------------
def analizza_classful(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except:
        return None

    primo = int(ip_str.split(".")[0])

    if 1 <= primo <= 126:
        classe = "A"; mask = "255.0.0.0"
    elif 128 <= primo <= 191:
        classe = "B"; mask = "255.255.0.0"
    elif 192 <= primo <= 223:
        classe = "C"; mask = "255.255.255.0"
    else:
        return {"classe": "Speciale"}

    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    hosts = list(network.hosts())
    return {
        "classe": classe,
        "mask": mask,
        "rete": str(network.network_address),
        "broadcast": str(network.broadcast_address),
        "range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
        "hosts": len(hosts),
        "tipo": "Privato" if ip.is_private else "Pubblico"
    }

# -------------------- Classless --------------------
def analizza_classless(cidr):
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except:
        return None

    hosts = list(net.hosts())
    return {
        "prefix": str(net.prefixlen),
        "rete": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
        "hosts": len(hosts),
        "tipo": "Privato" if net.is_private else "Pubblico"
    }

# -------------------- SUBNETTING SEMPLICE --------------------
def dividi_in_n_subnet(network, n):
    net = ipaddress.IPv4Network(network, strict=False)
    bits = (n - 1).bit_length()
    new_prefix = net.prefixlen + bits
    return [str(n) for n in net.subnets(new_prefix=new_prefix)]

def dividi_per_host(network, host_count):
    net = ipaddress.IPv4Network(network, strict=False)
    needed_hosts = host_count + 2

    new_prefix = 32
    while (2 ** (32 - new_prefix)) < needed_hosts:
        new_prefix -= 1

    return [str(n) for n in net.subnets(new_prefix=new_prefix)]

# -------------------- VLSM --------------------
def calcola_vlsm(network_base, richieste):
    """
    network_base: es '192.168.1.0/24'
    richieste: lista host es [50, 20, 5]
    """
    try:
        base_net = ipaddress.ip_network(network_base, strict=False)
    except:
        return None, "Rete base non valida."

    richieste = sorted(richieste, reverse=True)

    risultati = []
    current_ip = base_net.network_address

    for host in richieste:
        needed = host + 2
        bits = math.ceil(math.log2(needed))
        prefix = 32 - bits

        if prefix < base_net.prefixlen:
            return None, f"Impossibile allocare {host} host."

        subnet = ipaddress.ip_network(f"{current_ip}/{prefix}", strict=False)

        risultati.append({
            "richiesta_host": host,
            "network": str(subnet.network_address),
            "broadcast": str(subnet.broadcast_address),
            "mask": str(subnet.netmask),
            "prefix": prefix,
            "range": f"{subnet.network_address + 1} - {subnet.broadcast_address - 1}",
            "host_disponibili": subnet.num_addresses - 2
        })

        current_ip = subnet.broadcast_address + 1

    return risultati, None

# -------------------- ROUTES WEB --------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/converti", methods=["POST"])
def converti():
    valore = request.form["valore"]
    base = request.form["base"]
    return converti_numero(valore, base) or {"errore": "Valore non valido"}

@app.route("/ipv4", methods=["POST"])
def ipv4():
    valore = request.form["valore"]
    tipo = request.form["tipo"]

    if tipo == "dec_to_bin":
        r = ipv4_dec_to_bin(valore)
    else:
        r = ipv4_bin_to_dec(valore)

    return {"risultato": r} if r else {"errore": "IPv4 non valido"}

@app.route("/ipv6", methods=["POST"])
def ipv6():
    valore = request.form["valore"]
    tipo = request.form["tipo"]

    if tipo == "hex_to_bin":
        r = ipv6_hex_to_bin(valore)
    else:
        r = ipv6_bin_to_hex(valore)

    return {"risultato": r} if r else {"errore": "IPv6 non valido"}

@app.route("/classful", methods=["POST"])
def classful():
    valore = request.form["valore"]
    r = analizza_classful(valore)
    return r or {"errore": "IP non valido"}

@app.route("/classless", methods=["POST"])
def classless():
    valore = request.form["valore"]
    r = analizza_classless(valore)
    return r or {"errore": "CIDR non valido"}

@app.route("/subnetting", methods=["POST"])
def subnetting():
    network = request.form["network"]
    mode = request.form["mode"]
    value = request.form["value"]

    try:
        if mode == "num":
            result = dividi_in_n_subnet(network, int(value))
        else:
            result = dividi_per_host(network, int(value))

        return {"subnets": result}
    except:
        return {"errore": "Input non valido"}

# -------------------- ROUTE VLSM --------------------
@app.route("/vlsm", methods=["POST"])
def vlsm():
    network = request.form["network"]
    hosts_raw = request.form["hosts"]

    try:
        hosts = [int(x) for x in hosts_raw.split(",") if x.strip().isdigit()]
    except:
        return {"errore": "Lista host non valida"}

    result, error = calcola_vlsm(network, hosts)

    if error:
        return {"errore": error}
    return {"vlsm": result}

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
