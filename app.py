from flask import Flask, render_template, request, jsonify
import ipaddress
import math

app = Flask(__name__)

# -------------------- Conversione numerica --------------------
def converti_numero(valore, base):
    try:
        if base == "Decimale":
            n = int(valore)
        elif base == "Binario":
            n = int(valore, 2)
        elif base == "Ottale":
            n = int(valore, 8)
        elif base == "Esadecimale":
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

# -------------------- IPv4 --------------------
def ipv4_dec_to_bin(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts)!=4 or any(p<0 or p>255 for p in parts): return None
        return ".".join(format(p,"08b") for p in parts)
    except: return None

def ipv4_bin_to_dec(ip):
    try:
        parts = ip.split(".")
        if len(parts)!=4: return None
        return ".".join(str(int(p,2)) for p in parts)
    except: return None

# -------------------- IPv6 --------------------
def ipv6_hex_to_bin(ip):
    try:
        addr = ipaddress.IPv6Address(ip)
        bin_str = bin(int(addr))[2:].zfill(128)
        return ".".join(bin_str[i:i+16] for i in range(0,128,16))
    except: return None

def ipv6_bin_to_hex(bits):
    try:
        bits = bits.replace(".","")
        if len(bits)!=128: return None
        addr = ipaddress.IPv6Address(int(bits,2))
        return str(addr.compressed)
    except: return None

# -------------------- Classful --------------------
def analizza_classful(ip_str):
    try: ip = ipaddress.IPv4Address(ip_str)
    except: return None
    primo=int(ip_str.split(".")[0])
    if 1<=primo<=126: classe, mask = "A","255.0.0.0"
    elif 128<=primo<=191: classe, mask="B","255.255.0.0"
    elif 192<=primo<=223: classe, mask="C","255.255.255.0"
    else: return {"classe":"Speciale"}
    net=ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    hosts=list(net.hosts())
    return {
        "classe":classe,
        "mask":mask,
        "rete":str(net.network_address),
        "broadcast":str(net.broadcast_address),
        "range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
        "hosts":len(hosts),
        "tipo":"Privato" if ip.is_private else "Pubblico"
    }

# -------------------- Classless --------------------
def analizza_classless(cidr):
    try:
        net=ipaddress.IPv4Network(cidr, strict=False)
    except: return None
    hosts=list(net.hosts())
    return {
        "prefix":net.prefixlen,
        "rete":str(net.network_address),
        "broadcast":str(net.broadcast_address),
        "range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
        "hosts":len(hosts),
        "tipo":"Privato" if net.is_private else "Pubblico"
    }

# -------------------- VLSM --------------------
def vlsm_subnetting(network_base, host_requirements):
    try: base_network=ipaddress.ip_network(network_base, strict=False)
    except: return None, "Rete base non valida."
    reqs=sorted([int(h) for h in host_requirements if int(h)>0], reverse=True)
    if not reqs: return None,"Nessuna richiesta host valida."
    result=[]
    current=int(base_network.network_address)
    max_addr=int(base_network.broadcast_address)
    for req in reqs:
        needed=req+2
        bits=math.ceil(math.log2(needed))
        prefix=32-bits
        if prefix<base_network.prefixlen:
            return None,f"Impossibile allocare subnet per {req} host."
        candidate=ipaddress.ip_network((ipaddress.ip_address(current),prefix), strict=False)
        if int(candidate.broadcast_address)>max_addr:
            return None,f"Spazio insufficiente per {req} host."
        hosts_available=candidate.num_addresses-2 if candidate.num_addresses>=2 else 0
        first_host=candidate.network_address+1 if hosts_available>=1 else None
        last_host=candidate.broadcast_address-1 if hosts_available>=1 else None
        result.append({
            "richiesti":req,
            "network":str(candidate.network_address),
            "broadcast":str(candidate.broadcast_address),
            "mask":str(candidate.netmask),
            "prefix":candidate.prefixlen,
            "host_disponibili":hosts_available,
            "range":f"{first_host} - {last_host}" if first_host and last_host else "N/A"
        })
        current=int(candidate.broadcast_address)+1
    return result,None

# -------------------- Routes --------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/converti", methods=["POST"])
def api_converti():
    data=request.json
    res=converti_numero(data.get("valore"),data.get("base"))
    return jsonify(res or {"errore":"Valore non valido"})

@app.route("/api/ipv4", methods=["POST"])
def api_ipv4():
    data=request.json
    tipo=data.get("tipo"); val=data.get("valore")
    if tipo=="dec_to_bin": r=ipv4_dec_to_bin(val)
    else: r=ipv4_bin_to_dec(val)
    return jsonify({"risultato":r} if r else {"errore":"IPv4 non valido"})

@app.route("/api/ipv6", methods=["POST"])
def api_ipv6():
    data=request.json
    tipo=data.get("tipo"); val=data.get("valore")
    if tipo=="hex_to_bin": r=ipv6_hex_to_bin(val)
    else: r=ipv6_bin_to_hex(val)
    return jsonify({"risultato":r} if r else {"errore":"IPv6 non valido"})

@app.route("/api/classful", methods=["POST"])
def api_classful():
    data=request.json
    val=data.get("valore")
    r=analizza_classful(val)
    return jsonify(r or {"errore":"IP non valido"})

@app.route("/api/classless", methods=["POST"])
def api_classless():
    data=request.json
    val=data.get("valore")
    r=analizza_classless(val)
    return jsonify(r or {"errore":"CIDR non valido"})

@app.route("/api/vlsm", methods=["POST"])
def api_vlsm():
    data=request.json
    rete=data.get("rete")
    hosts=data.get("hosts")
    r,err=vlsm_subnetting(rete, hosts)
    if err: return jsonify({"errore":err})
    return jsonify({"subnets":r})

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
