import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import math

# -------------------- Utility --------------------
def copia_testo(testo):
    """Copia testo negli appunti mostrando conferma o errore."""
    try:
        root.clipboard_clear()
        root.clipboard_append(testo)
        messagebox.showinfo("Copiato", "Testo copiato negli appunti!")
    except Exception as e:
        messagebox.showerror("Errore copia", str(e))

def safe_int(s, default=0):
    try:
        return int(s)
    except:
        return default

# -------------------- VLSM Logic --------------------
def vlsm_subnetting(network_base, host_requirements):
    """
    Calcola VLSM per rete base (es. '192.168.10.0/24') e lista richieste host.
    Restituisce (lista_subnet, errore) dove lista_subnet è lista di dict.
    """
    try:
        base_network = ipaddress.ip_network(network_base, strict=False)
    except Exception:
        return None, "Rete base non valida."

    # Ordina decrescente le richieste (più grande prima)
    reqs = sorted([int(h) for h in host_requirements if int(h) > 0], reverse=True)
    if not reqs:
        return None, "Nessuna richiesta host valida."

    results = []
    current = int(base_network.network_address)
    max_addr = int(base_network.broadcast_address)

    for req in reqs:
        needed = req + 2  # include network + broadcast
        bits = math.ceil(math.log2(needed))
        subnet_prefix = 32 - bits

        # non possiamo avere prefix più piccolo della rete base (subnet più grande della base)
        if subnet_prefix < base_network.prefixlen:
            return None, f"Impossibile allocare subnet per {req} host (richiesto prefix /{subnet_prefix})."

        try:
            candidate = ipaddress.ip_network((ipaddress.ip_address(current), subnet_prefix), strict=False)
        except Exception:
            return None, "Errore nella creazione della subnet candidata."

        if int(candidate.broadcast_address) > max_addr:
            return None, f"Spazio insufficiente nella rete base per allocare {req} host."

        hosts_available = max(candidate.num_addresses - 2, 0)
        first_host = candidate.network_address + 1 if hosts_available >= 1 else None
        last_host = candidate.broadcast_address - 1 if hosts_available >= 1 else None

        results.append({
            "richiesti": req,
            "network": str(candidate.network_address),
            "broadcast": str(candidate.broadcast_address),
            "mask": str(candidate.netmask),
            "prefix": candidate.prefixlen,
            "host_disponibili": hosts_available,
            "range": f"{first_host} - {last_host}" if first_host and last_host else "N/A"
        })

        current = int(candidate.broadcast_address) + 1

    return results, None

# -------------------- Conversion & IP Analysis Logic --------------------
def convert_number_logic(valore, base):
    if base == "Decimale":
        n = int(valore)
    elif base == "Binario":
        n = int(valore, 2)
    elif base == "Ottale":
        n = int(valore, 8)
    elif base == "Esadecimale":
        n = int(valore, 16)
    else:
        raise ValueError("Base non supportata")
    return n

def analyze_classful(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except Exception:
        return None
    primo = int(ip_str.split('.')[0])
    if 1 <= primo <= 126:
        classe, mask = 'A', '255.0.0.0'
    elif 128 <= primo <= 191:
        classe, mask = 'B', '255.255.0.0'
    elif 192 <= primo <= 223:
        classe, mask = 'C', '255.255.255.0'
    elif 224 <= primo <= 239:
        return {"Classe":"D (Multicast)"}
    else:
        return {"Classe":"E (Riservata/Experimental)"}
    net = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
    hosts = list(net.hosts())
    return {
        "Classe": classe,
        "Subnet Mask": mask,
        "Rete": str(net.network_address),
        "Broadcast": str(net.broadcast_address),
        "Range Host": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
        "Numero Host": len(hosts),
        "Tipo": "Privato" if ip.is_private else "Pubblico"
    }

def analyze_classless(cidr_str):
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
    except Exception:
        return None
    hosts = list(net.hosts())
    return {
        "Prefix": net.prefixlen,
        "Rete": str(net.network_address),
        "Broadcast": str(net.broadcast_address),
        "Range Host": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
        "Numero Host": len(hosts),
        "Tipo": "Privato" if net.is_private else "Pubblico"
    }

# -------------------- GUI: setup colors & styles --------------------
root = tk.Tk()
root.title("CONVERTITORE+")
root.geometry("820x760")
root.resizable(False, False)
# Icon (opzionale): assicurati che icon.ico esista nella stessa cartella
try:
    root.iconbitmap("icon.ico")
except Exception:
    pass

# Color scheme
BG = "#1e1e1e"
FRAME_BG = "#2d2d2d"
FG = "#ffffff"
ACCENT = "#167913"   # green accent
INVERT = "#000000"
BTN_ACTIVE = "#1f7a1f"

root.configure(bg=BG)

style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook", background=BG, borderwidth=0)
style.configure("TNotebook.Tab", background=FRAME_BG, foreground=FG, padding=[18, 10])
style.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", INVERT)])

# -------------------- Button factory --------------------
def create_button(master, text, cmd, width=16):
    b = tk.Button(master, text=text, command=cmd,
                  font=("Helvetica", 12, "bold"),
                  bg=ACCENT, fg=INVERT,
                  activebackground=BTN_ACTIVE, activeforeground=FG,
                  relief="flat", width=width, padx=6, pady=6)
    return b

def create_copy_button(master, text, cmd):
    b = tk.Button(master, text=text, command=cmd,
                  font=("Helvetica", 10, "bold"),
                  bg="#333333", fg=FG,
                  activebackground="#444444", activeforeground=FG,
                  relief="flat", width=8)
    return b

# -------------------- Notebook and tabs --------------------
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both", padx=16, pady=16)

# -------------------- Tab: Sistemi Numerici --------------------
tab_num = tk.Frame(notebook, bg=BG)
notebook.add(tab_num, text="Sistemi Numerici")

tk.Label(tab_num, text="Convertitore Base Numerica", font=("Helvetica",18,"bold"), fg=ACCENT, bg=BG).pack(pady=(14,8))

frame_num_input = tk.Frame(tab_num, bg=BG)
frame_num_input.pack(pady=6, anchor="w", padx=12)

tk.Label(frame_num_input, text="Numero:", font=("Helvetica",13), fg=FG, bg=BG).pack(side=tk.LEFT, padx=(0,8))
entry_num = tk.Entry(frame_num_input, font=("Helvetica",13), width=22, justify="center",
                     bg=FRAME_BG, fg=FG, insertbackground=FG)
entry_num.pack(side=tk.LEFT)

base_var = tk.StringVar(value="Decimale")
opt_num = tk.OptionMenu(frame_num_input, base_var, "Decimale", "Binario", "Ottale", "Esadecimale")
opt_num.config(bg=FRAME_BG, fg=FG, font=("Helvetica",12), width=12)
opt_num["menu"].config(bg=FRAME_BG, fg=FG, font=("Helvetica",12))
opt_num.pack(side=tk.LEFT, padx=10)

btn_frame_num = tk.Frame(tab_num, bg=BG)
btn_frame_num.pack(pady=8, anchor="w", padx=12)
create_button(btn_frame_num, "Converti", lambda: on_convert_number(), width=14).pack(side=tk.LEFT, padx=6)
create_button(btn_frame_num, "Pulisci", lambda: on_clear_number(), width=14).pack(side=tk.LEFT, padx=6)

frame_num_res = tk.Frame(tab_num, bg=BG)
frame_num_res.pack(pady=8, fill="x", padx=12)
var_dec = tk.StringVar(); var_bin = tk.StringVar(); var_oct = tk.StringVar(); var_hex = tk.StringVar()

def row_result(parent, label_text, var):
    f = tk.Frame(parent, bg=BG)
    f.pack(fill="x", pady=4, anchor="w")
    tk.Label(f, text=label_text, font=("Helvetica",12), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
    tk.Label(f, textvariable=var, font=("Helvetica",12), fg=ACCENT, bg=BG).pack(side=tk.LEFT, padx=10)
    create_copy_button(f, "Copia", lambda v=var: copia_testo(v.get())).pack(side=tk.LEFT, padx=12)

row_result(frame_num_res, "Decimale:", var_dec)
row_result(frame_num_res, "Binario:", var_bin)
row_result(frame_num_res, "Ottale:", var_oct)
row_result(frame_num_res, "Esadecimale:", var_hex)

def on_convert_number():
    valore = entry_num.get().strip()
    base = base_var.get()
    try:
        n = convert_number_logic(valore, base)
        var_dec.set(str(n))
        var_bin.set(bin(n)[2:])
        var_oct.set(oct(n)[2:])
        var_hex.set(hex(n)[2:].upper())
    except Exception:
        messagebox.showerror("Errore", "Inserisci un numero valido per la base selezionata.")

def on_clear_number():
    entry_num.delete(0, tk.END)
    var_dec.set(""); var_bin.set(""); var_oct.set(""); var_hex.set("")

# -------------------- Tab: IPv4 --------------------
tab_ipv4 = tk.Frame(notebook, bg=BG)
notebook.add(tab_ipv4, text="IPv4")

tk.Label(tab_ipv4, text="Convertitore IPv4", font=("Helvetica",18,"bold"), fg=ACCENT, bg=BG).pack(pady=(14,8))
frame_ipv4_in = tk.Frame(tab_ipv4, bg=BG)
frame_ipv4_in.pack(pady=6, anchor="w", padx=12)
tk.Label(frame_ipv4_in, text="Indirizzo:", font=("Helvetica",13), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
entry_ipv4 = tk.Entry(frame_ipv4_in, font=("Helvetica",13), width=28, justify="center",
                      bg=FRAME_BG, fg=FG, insertbackground=FG)
entry_ipv4.pack(side=tk.LEFT, padx=6)

frame_ipv4_btn = tk.Frame(tab_ipv4, bg=BG)
frame_ipv4_btn.pack(pady=8, anchor="w", padx=12)
create_button(frame_ipv4_btn, "Decimale → Binario", lambda: on_ipv4_dec_bin()).pack(side=tk.LEFT, padx=6)
create_button(frame_ipv4_btn, "Binario → Decimale", lambda: on_ipv4_bin_dec()).pack(side=tk.LEFT, padx=6)
create_button(frame_ipv4_btn, "Pulisci", lambda: on_ipv4_clear()).pack(side=tk.LEFT, padx=6)

var_ipv4_res = tk.StringVar()
tk.Label(tab_ipv4, text="Risultato:", font=("Helvetica",14,"bold"), fg=FG, bg=BG).pack(pady=(8,2))
tk.Label(tab_ipv4, textvariable=var_ipv4_res, font=("Helvetica",13), fg=ACCENT, bg=BG, wraplength=760, justify="left").pack(pady=(0,6))
create_copy_button(tab_ipv4, "Copia", lambda: copia_testo(var_ipv4_res.get())).pack()

def on_ipv4_dec_bin():
    ip = entry_ipv4.get().strip()
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            raise ValueError
        var_ipv4_res.set(".".join(format(p, "08b") for p in parts))
    except Exception:
        messagebox.showerror("Errore", "Inserisci un IPv4 valido, es: 192.168.1.1")

def on_ipv4_bin_dec():
    ip = entry_ipv4.get().strip()
    try:
        parts = ip.split(".")
        if len(parts) != 4 or not all(len(p) == 8 and all(c in "01" for c in p) for p in parts):
            raise ValueError
        var_ipv4_res.set(".".join(str(int(p, 2)) for p in parts))
    except Exception:
        messagebox.showerror("Errore", "Inserisci un IPv4 binario valido, es: 11000000.10101000.00000001.00000001")

def on_ipv4_clear():
    entry_ipv4.delete(0, tk.END)
    var_ipv4_res.set("")

# -------------------- Tab: IPv6 --------------------
tab_ipv6 = tk.Frame(notebook, bg=BG)
notebook.add(tab_ipv6, text="IPv6")

tk.Label(tab_ipv6, text="Convertitore IPv6", font=("Helvetica",18,"bold"), fg=ACCENT, bg=BG).pack(pady=(14,8))
frame_ipv6_in = tk.Frame(tab_ipv6, bg=BG)
frame_ipv6_in.pack(pady=6, anchor="w", padx=12)
tk.Label(frame_ipv6_in, text="Indirizzo:", font=("Helvetica",13), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
entry_ipv6 = tk.Entry(frame_ipv6_in, font=("Helvetica",13), width=40, justify="center",
                      bg=FRAME_BG, fg=FG, insertbackground=FG)
entry_ipv6.pack(side=tk.LEFT, padx=6)

frame_ipv6_btn = tk.Frame(tab_ipv6, bg=BG)
frame_ipv6_btn.pack(pady=8, anchor="w", padx=12)
create_button(frame_ipv6_btn, "Esadecimale → Binario", lambda: on_ipv6_hex_bin()).pack(side=tk.LEFT, padx=6)
create_button(frame_ipv6_btn, "Binario → Esadecimale", lambda: on_ipv6_bin_hex()).pack(side=tk.LEFT, padx=6)
create_button(frame_ipv6_btn, "Pulisci", lambda: on_ipv6_clear()).pack(side=tk.LEFT, padx=6)

var_ipv6_res = tk.StringVar()
tk.Label(tab_ipv6, text="Risultato:", font=("Helvetica",14,"bold"), fg=FG, bg=BG).pack(pady=(8,2))
tk.Label(tab_ipv6, textvariable=var_ipv6_res, font=("Helvetica",11), fg=ACCENT, bg=BG, wraplength=760, justify="left").pack(pady=(0,6))
create_copy_button(tab_ipv6, "Copia", lambda: copia_testo(var_ipv6_res.get())).pack()

def on_ipv6_hex_bin():
    ip = entry_ipv6.get().strip()
    try:
        addr = ipaddress.IPv6Address(ip)
        bin_str = bin(int(addr))[2:].zfill(128)
        var_ipv6_res.set(".".join(bin_str[i:i+16] for i in range(0, 128, 16)))
    except Exception:
        messagebox.showerror("Errore", "Inserisci un IPv6 valido, es: 2001:db8::1")

def on_ipv6_bin_hex():
    ip = entry_ipv6.get().strip().replace(".", "")
    try:
        if len(ip) != 128 or not all(c in "01" for c in ip):
            raise ValueError
        dec_val = int(ip, 2)
        addr = ipaddress.IPv6Address(dec_val)
        var_ipv6_res.set(str(addr.compressed))
    except Exception:
        messagebox.showerror("Errore", "Inserisci 128 bit binari validi per un IPv6.")

def on_ipv6_clear():
    entry_ipv6.delete(0, tk.END)
    var_ipv6_res.set("")

# -------------------- Tab: Analisi IP Classful --------------------
tab_classful = tk.Frame(notebook, bg=BG)
notebook.add(tab_classful, text="Analisi Classful")

tk.Label(tab_classful, text="Analisi Indirizzo IPv4 (Classful)", font=("Helvetica",18,"bold"), fg=ACCENT, bg=BG).pack(pady=(14,8))
frame_classful_in = tk.Frame(tab_classful, bg=BG)
frame_classful_in.pack(pady=6, anchor="w", padx=12)
tk.Label(frame_classful_in, text="Indirizzo:", font=("Helvetica",13), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
entry_ip_analizza = tk.Entry(frame_classful_in, font=("Helvetica",13), width=28, justify="center",
                             bg=FRAME_BG, fg=FG, insertbackground=FG)
entry_ip_analizza.pack(side=tk.LEFT, padx=6)

frame_classful_btn = tk.Frame(tab_classful, bg=BG)
frame_classful_btn.pack(pady=8, anchor="w", padx=12)
create_button(frame_classful_btn, "Analizza", lambda: on_analizza_classful()).pack(side=tk.LEFT, padx=6)
create_button(frame_classful_btn, "Pulisci", lambda: on_clear_classful()).pack(side=tk.LEFT, padx=6)

classful_vars = {
    "Classe": tk.StringVar(),
    "Subnet Mask": tk.StringVar(),
    "Rete": tk.StringVar(),
    "Broadcast": tk.StringVar(),
    "Range Host": tk.StringVar(),
    "Numero Host": tk.StringVar(),
    "Tipo": tk.StringVar()
}
res_frame_classful = tk.Frame(tab_classful, bg=BG)
res_frame_classful.pack(pady=6, padx=12, anchor="w")
for k, v in classful_vars.items():
    f = tk.Frame(res_frame_classful, bg=BG)
    f.pack(anchor="w", pady=2)
    tk.Label(f, text=f"{k}:", font=("Helvetica",12), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
    tk.Label(f, textvariable=v, font=("Helvetica",12), fg=ACCENT, bg=BG).pack(side=tk.LEFT, padx=10)
    create_copy_button(f, "Copia", lambda vv=v: copia_testo(vv.get())).pack(side=tk.LEFT, padx=8)

def on_analizza_classful():
    ip = entry_ip_analizza.get().strip()
    info = analyze_classful(ip)
    if not info:
        messagebox.showerror("Errore", "IP non valido.")
        return
    classful_vars["Classe"].set(info.get("Classe", "N/A"))
    classful_vars["Subnet Mask"].set(info.get("Subnet Mask", "N/A"))
    classful_vars["Rete"].set(info.get("Rete", "N/A"))
    classful_vars["Broadcast"].set(info.get("Broadcast", "N/A"))
    classful_vars["Range Host"].set(info.get("Range Host", "N/A"))
    classful_vars["Numero Host"].set(info.get("Numero Host", "N/A"))
    classful_vars["Tipo"].set(info.get("Tipo", "N/A"))

def on_clear_classful():
    entry_ip_analizza.delete(0, tk.END)
    for v in classful_vars.values():
        v.set("")

# -------------------- Tab: Analisi IP Classless --------------------
tab_classless = tk.Frame(notebook, bg=BG)
notebook.add(tab_classless, text="Analisi Classless")

tk.Label(tab_classless, text="Analisi IPv4 (CIDR)", font=("Helvetica",18,"bold"), fg=ACCENT, bg=BG).pack(pady=(14,8))
frame_cless_in = tk.Frame(tab_classless, bg=BG)
frame_cless_in.pack(pady=6, anchor="w", padx=12)
tk.Label(frame_cless_in, text="Network/CIDR:", font=("Helvetica",13), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
entry_classless = tk.Entry(frame_cless_in, font=("Helvetica",13), width=28, justify="center",
                           bg=FRAME_BG, fg=FG, insertbackground=FG)
entry_classless.pack(side=tk.LEFT, padx=6)

frame_cless_btn = tk.Frame(tab_classless, bg=BG)
frame_cless_btn.pack(pady=8, anchor="w", padx=12)
create_button(frame_cless_btn, "Analizza", lambda: on_analyze_classless()).pack(side=tk.LEFT, padx=6)
create_button(frame_cless_btn, "Pulisci", lambda: on_clear_classless()).pack(side=tk.LEFT, padx=6)

cless_vars = {
    "Prefix": tk.StringVar(),
    "Rete": tk.StringVar(),
    "Broadcast": tk.StringVar(),
    "Range Host": tk.StringVar(),
    "Numero Host": tk.StringVar(),
    "Tipo": tk.StringVar()
}
res_frame_cless = tk.Frame(tab_classless, bg=BG)
res_frame_cless.pack(pady=6, padx=12, anchor="w")
for k, v in cless_vars.items():
    f = tk.Frame(res_frame_cless, bg=BG)
    f.pack(anchor="w", pady=2)
    tk.Label(f, text=f"{k}:", font=("Helvetica",12), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
    tk.Label(f, textvariable=v, font=("Helvetica",12), fg=ACCENT, bg=BG).pack(side=tk.LEFT, padx=10)
    create_copy_button(f, "Copia", lambda vv=v: copia_testo(vv.get())).pack(side=tk.LEFT, padx=8)

def on_analyze_classless():
    s = entry_classless.get().strip()
    info = analyze_classless(s)
    if not info:
        messagebox.showerror("Errore", "CIDR non valido.")
        return
    cless_vars["Prefix"].set(info.get("Prefix", "N/A"))
    cless_vars["Rete"].set(info.get("Rete", "N/A"))
    cless_vars["Broadcast"].set(info.get("Broadcast", "N/A"))
    cless_vars["Range Host"].set(info.get("Range Host", "N/A"))
    cless_vars["Numero Host"].set(info.get("Numero Host", "N/A"))
    cless_vars["Tipo"].set(info.get("Tipo", "N/A"))

def on_clear_classless():
    entry_classless.delete(0, tk.END)
    for v in cless_vars.values():
        v.set("")

# -------------------- Tab: VLSM --------------------
tab_vlsm = tk.Frame(notebook, bg=BG)
notebook.add(tab_vlsm, text="VLSM")

tk.Label(tab_vlsm, text="VLSM Subnet Calculator", font=("Helvetica",18,"bold"), fg=ACCENT, bg=BG).pack(pady=(14,8))

frame_vlsm_in = tk.Frame(tab_vlsm, bg=BG)
frame_vlsm_in.pack(pady=6, anchor="w", padx=12)
tk.Label(frame_vlsm_in, text="Rete Base (CIDR):", font=("Helvetica",13), fg=FG, bg=BG).pack(side=tk.LEFT, padx=6)
entry_vlsm_base = tk.Entry(frame_vlsm_in, font=("Helvetica",13), width=28, justify="center",
                           bg=FRAME_BG, fg=FG, insertbackground=FG)
entry_vlsm_base.pack(side=tk.LEFT, padx=6)
entry_vlsm_base.insert(0, "192.168.10.0/24")

frame_vlsm_hosts = tk.Frame(tab_vlsm, bg=BG)
frame_vlsm_hosts.pack(pady=8, padx=12, fill="x", anchor="w")
tk.Label(frame_vlsm_hosts, text="Richieste Host (aggiungi righe):", font=("Helvetica",13), fg=FG, bg=BG).pack(anchor="w")

hosts_rows_frame = tk.Frame(frame_vlsm_hosts, bg=BG)
hosts_rows_frame.pack(anchor="w", pady=6)

vlsm_rows = []

def add_vlsm_row(value=""):
    row = tk.Frame(hosts_rows_frame, bg=BG)
    row.pack(anchor="w", pady=3)
    e = tk.Entry(row, font=("Helvetica",12), width=10, justify="center",
                 bg=FRAME_BG, fg=FG, insertbackground=FG)
    e.pack(side=tk.LEFT, padx=(0,8))
    e.insert(0, str(value))
    lbl = tk.Label(row, text="host", font=("Helvetica",12), fg=FG, bg=BG)
    lbl.pack(side=tk.LEFT, padx=(0,8))
    btn_del = tk.Button(row, text="Rimuovi", command=lambda r=row: remove_vlsm_row(r),
                        font=("Helvetica",10,"bold"), bg="#883333", fg=FG, relief="flat")
    btn_del.pack(side=tk.LEFT, padx=6)
    vlsm_rows.append((row, e))

def remove_vlsm_row(row):
    for tup in vlsm_rows:
        if tup[0] == row:
            tup[0].destroy()
            vlsm_rows.remove(tup)
            break

# aggiungi righe di default
if not vlsm_rows:
    for val in [50, 20, 5]:
        add_vlsm_row(val)

frame_vlsm_controls = tk.Frame(tab_vlsm, bg=BG)
frame_vlsm_controls.pack(pady=8, anchor="w", padx=12)
create_button(frame_vlsm_controls, "Aggiungi Riga", lambda: add_vlsm_row("")).pack(side=tk.LEFT, padx=6)
create_button(frame_vlsm_controls, "Calcola VLSM", lambda: on_calcola_vlsm()).pack(side=tk.LEFT, padx=6)
create_button(frame_vlsm_controls, "Pulisci Tutto", lambda: on_clear_vlsm()).pack(side=tk.LEFT, padx=6)

frame_vlsm_out = tk.Frame(tab_vlsm, bg=BG)
frame_vlsm_out.pack(pady=8, padx=12, fill="both", expand=True)
txt_vlsm = tk.Text(frame_vlsm_out, font=("Courier New", 11), bg="#0f0f0f", fg=FG, wrap="none", height=12)
txt_vlsm.pack(side=tk.LEFT, fill="both", expand=True)
scroll_vlsm = tk.Scrollbar(frame_vlsm_out, command=txt_vlsm.yview)
scroll_vlsm.pack(side=tk.RIGHT, fill="y")
txt_vlsm.config(yscrollcommand=scroll_vlsm.set)
create_copy_button(frame_vlsm_out, "Copia Output", lambda: copia_testo(txt_vlsm.get("1.0", tk.END))).pack(pady=6)

def on_calcola_vlsm():
    base = entry_vlsm_base.get().strip()
    hosts = []
    for _, ent in vlsm_rows:
        val = ent.get().strip()
        if val:
            try:
                n = int(val)
                if n > 0:
                    hosts.append(n)
            except:
                messagebox.showerror("Errore", f"Valore host non valido: {val}")
                return
    if not hosts:
        messagebox.showerror("Errore", "Inserisci almeno una richiesta host valida.")
        return

    result, err = vlsm_subnetting(base, hosts)
    txt_vlsm.delete("1.0", tk.END)
    if err:
        txt_vlsm.insert(tk.END, f"ERRORE: {err}\n")
        return

    header = f"{'Rich.':>6}  {'Network':<18}  {'Mask':<15}  {'CIDR':<5}  {'Hosts':>6}  {'Range':<23}  {'Broadcast':<15}\n"
    txt_vlsm.insert(tk.END, header)
    txt_vlsm.insert(tk.END, "-" * (len(header) + 30) + "\n")
    for r in result:
        line = f"{r['richiesti']:>6}  {r['network']:<18}  {r['mask']:<15}  /{r['prefix']:<3}  {r['host_disponibili']:>6}  {r['range']:<23}  {r['broadcast']:<15}\n"
        txt_vlsm.insert(tk.END, line)
    txt_vlsm.insert(tk.END, "\nNote: le richieste sono allocate in ordine decrescente (sottoreti più grandi prime).\n")

def on_clear_vlsm():
    entry_vlsm_base.delete(0, tk.END)
    entry_vlsm_base.insert(0, "192.168.10.0/24")
    for row, ent in vlsm_rows[:]:
        row.destroy()
        vlsm_rows.remove((row, ent))
    for _ in range(3):
        add_vlsm_row("")
    txt_vlsm.delete("1.0", tk.END)

# -------------------- Tab: Info --------------------
tab_info = tk.Frame(notebook, bg=BG)
notebook.add(tab_info, text="Info")

tk.Label(tab_info, text="CONVERTITORE+", font=("Helvetica",22,"bold"), fg=ACCENT, bg=BG).pack(pady=(16,6))
tk.Label(tab_info, text=(
    "Questa applicazione converte numeri tra sistemi numerici (Dec, Bin, Oct, Hex),\n"
    "gestisce conversione IPv4/IPv6 e analisi Classful/Classless.\n"
    "Include inoltre il calcolatore VLSM con interfaccia dinamica.\n\n"
    "Sviluppata in Python + Tkinter.\n\n"
    "Credits: Diego Valle\n"
    "Versione: 0.2 (agg. VLSM)\n"
), font=("Helvetica",12), fg=FG, bg=BG, justify="center").pack(pady=10)

# -------------------- Avvio --------------------
root.mainloop()
