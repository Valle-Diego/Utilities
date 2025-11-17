import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ipaddress
import math

# -------------------- Funzioni generali --------------------
def copia_testo(testo):
    root.clipboard_clear()
    root.clipboard_append(testo)
    messagebox.showinfo("Copiato", f"'{testo}' copiato negli appunti!")

# -------------------- Funzioni Sistemi Numerici --------------------
def converti_numero():
    valore = entry_num.get().strip()
    base = base_var.get()
    try:
        if base == "Decimale": n = int(valore)
        elif base == "Binario": n = int(valore, 2)
        elif base == "Ottale": n = int(valore, 8)
        elif base == "Esadecimale": n = int(valore, 16)
        else: raise ValueError
        risultato_dec.set(str(n))
        risultato_bin.set(bin(n)[2:])
        risultato_oct.set(oct(n)[2:])
        risultato_hex.set(hex(n)[2:].upper())
    except Exception:
        messagebox.showerror("Errore", "Inserisci un numero valido per la base selezionata.")

def pulisci_num():
    entry_num.delete(0, tk.END)
    risultato_dec.set(""); risultato_bin.set(""); risultato_oct.set(""); risultato_hex.set("")

# -------------------- Funzioni IPv4 --------------------
def ipv4_dec_bin():
    ip = entry_ipv4.get().strip()
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts)!=4 or any(p<0 or p>255 for p in parts): raise ValueError
        risultato_ipv4.set(".".join(format(p,"08b") for p in parts))
    except Exception:
        messagebox.showerror("Errore","Inserisci un IPv4 valido, es: 192.168.1.1")

def ipv4_bin_dec():
    ip = entry_ipv4.get().strip()
    try:
        parts = ip.split(".")
        if len(parts)!=4 or not all(len(p)==8 and all(c in "01" for c in p) for p in parts): raise ValueError
        risultato_ipv4.set(".".join(str(int(p,2)) for p in parts))
    except Exception:
        messagebox.showerror("Errore","Inserisci un IPv4 binario valido, es: 11000000.10101000.00000001.00000001")

def pulisci_ipv4():
    entry_ipv4.delete(0, tk.END)
    risultato_ipv4.set("")

# -------------------- Funzioni IPv6 --------------------
def ipv6_hex_bin():
    ip = entry_ipv6.get().strip()
    try:
        addr = ipaddress.IPv6Address(ip)
        bin_str = bin(int(addr))[2:].zfill(128)
        risultato_ipv6.set(".".join(bin_str[i:i+16] for i in range(0,128,16)))
    except Exception:
        messagebox.showerror("Errore","Inserisci un IPv6 valido, es: 2001:db8::1")

def ipv6_bin_hex():
    ip = entry_ipv6.get().strip().replace(".","")
    try:
        if len(ip)!=128 or not all(c in "01" for c in ip): raise ValueError
        dec_val = int(ip,2)
        addr = ipaddress.IPv6Address(dec_val)
        risultato_ipv6.set(str(addr.compressed))
    except Exception:
        messagebox.showerror("Errore","Inserisci 128 bit binari validi per un IPv6.")

def pulisci_ipv6():
    entry_ipv6.delete(0, tk.END)
    risultato_ipv6.set("")

# -------------------- Funzioni Analisi IP Classful --------------------
def analizza_ip_classful(ip_str):
    try: ip = ipaddress.IPv4Address(ip_str)
    except ipaddress.AddressValueError:
        return {"Classe":"IP non valido","Subnet Mask":"N/A","Rete":"N/A","Broadcast":"N/A",
                "Range Host":"N/A","Numero Host":0,"Tipo":"N/A"}

    primo_octetto = int(ip_str.split('.')[0])
    if 1<=primo_octetto<=126: classe='A'; subnet_mask='255.0.0.0'
    elif 128<=primo_octetto<=191: classe='B'; subnet_mask='255.255.0.0'
    elif 192<=primo_octetto<=223: classe='C'; subnet_mask='255.255.255.0'
    elif 224<=primo_octetto<=239: classe='D (Multicast)'; subnet_mask=None
    else: classe='E (Riservata/Experimental)'; subnet_mask=None

    if classe in ['D (Multicast)','E (Riservata/Experimental)']:
        return {"Classe":classe,"Subnet Mask":subnet_mask,"Rete":None,"Broadcast":None,
                "Range Host":None,"Numero Host":0,"Tipo":"N/A"}

    network = ipaddress.IPv4Network(f"{ip_str}/{subnet_mask}",strict=False)
    hosts = list(network.hosts())
    range_host = f"{hosts[0]} - {hosts[-1]}" if hosts else None

    return {"Classe":classe,"Subnet Mask":subnet_mask,"Rete":str(network.network_address),
            "Broadcast":str(network.broadcast_address),"Range Host":range_host,
            "Numero Host":len(hosts),"Tipo":"Privato" if ip.is_private else "Pubblico"}

def analizza_ip_gui():
    ip = entry_ip_analizza.get().strip()
    info = analizza_ip_classful(ip)
    classe_var.set(info["Classe"])
    subnet_var.set(info["Subnet Mask"] or "N/A")
    rete_var.set(info["Rete"] or "N/A")
    broadcast_var.set(info["Broadcast"] or "N/A")
    range_var.set(info["Range Host"] or "N/A")
    numero_var.set(info["Numero Host"])
    tipo_var.set(info["Tipo"])

def pulisci_ip_analizza():
    entry_ip_analizza.delete(0, tk.END)
    classe_var.set(""); subnet_var.set(""); rete_var.set(""); broadcast_var.set("")
    range_var.set(""); numero_var.set(""); tipo_var.set("")

# -------------------- Funzioni Analisi IP Classless --------------------
def analizza_ip_classless(ip_cidr):
    try: net = ipaddress.IPv4Network(ip_cidr,strict=False)
    except Exception:
        return {"Subnet Prefix":"N/A","Rete":"N/A","Broadcast":"N/A","Range Host":"N/A",
                "Numero Host":0,"Tipo":"N/A"}
    hosts=list(net.hosts())
    range_host = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
    return {"Subnet Prefix":str(net.prefixlen),"Rete":str(net.network_address),
            "Broadcast":str(net.broadcast_address),"Range Host":range_host,
            "Numero Host":len(hosts),"Tipo":"Privato" if net.is_private else "Pubblico"}

def analizza_ip_classless_gui():
    ip = entry_ip_classless.get().strip()
    info = analizza_ip_classless(ip)
    cless_mask_var.set(info["Subnet Prefix"])
    cless_rete_var.set(info["Rete"])
    cless_broadcast_var.set(info["Broadcast"])
    cless_range_var.set(info["Range Host"])
    cless_num_var.set(info["Numero Host"])
    cless_tipo_var.set(info["Tipo"])

def pulisci_ip_classless():
    entry_ip_classless.delete(0, tk.END)
    cless_mask_var.set(""); cless_rete_var.set(""); cless_broadcast_var.set("")
    cless_range_var.set(""); cless_num_var.set(""); cless_tipo_var.set("")

# -------------------- Funzioni Subnetting --------------------
def format_subnet_info(net: ipaddress.IPv4Network):
    # safe handling for networks with no hosts (e.g., /31 /32)
    hosts = list(net.hosts())
    first_host = str(hosts[0]) if hosts else "N/A"
    last_host = str(hosts[-1]) if hosts else "N/A"
    usable = max(len(hosts), 0)
    return (f"Network: {net.network_address}/{net.prefixlen}\n"
            f"Subnet Mask: {net.netmask}\n"
            f"Broadcast: {net.broadcast_address}\n"
            f"Host range: {first_host} - {last_host}\n"
            f"Usable hosts: {usable}\n"
            "----------------------------------------\n")

def subnet_dividi_equal():
    txt_result_subnet.delete(1.0, tk.END)
    net_str = entry_subnet_network.get().strip()
    n_str = entry_subnet_n.get().strip()
    if not net_str or not n_str:
        messagebox.showerror("Errore", "Inserisci rete/CIDR e numero di sottoreti.")
        return
    try:
        base_net = ipaddress.IPv4Network(net_str, strict=False)
    except Exception:
        messagebox.showerror("Errore", "Rete/CIDR non valida. Esempio valido: 192.168.1.0/24")
        return
    try:
        n = int(n_str)
        if n <= 0:
            raise ValueError
    except Exception:
        messagebox.showerror("Errore", "Inserisci un numero di sottoreti valido (>0).")
        return

    # calcola quanti bit servono per ottenere almeno n sottoreti
    bits_needed = math.ceil(math.log2(n))
    new_prefix = base_net.prefixlen + bits_needed
    if new_prefix > 32:
        messagebox.showerror("Errore", "Impossibile creare così tante sottoreti da questa rete.")
        return

    # genera sottoreti di dimensione new_prefix
    subnets = list(base_net.subnets(new_prefix=new_prefix))
    txt_result_subnet.insert(tk.END, f"Da {base_net} -> creerò {len(subnets)} sottoreti con prefisso /{new_prefix}\n\n")
    for i, s in enumerate(subnets, start=1):
        txt_result_subnet.insert(tk.END, f"Sottorete {i}:\n")
        txt_result_subnet.insert(tk.END, format_subnet_info(s))

def subnet_dividi_by_hosts():
    txt_result_subnet.delete(1.0, tk.END)
    net_str = entry_subnet_network.get().strip()
    hosts_str = entry_subnet_hosts.get().strip()
    if not net_str or not hosts_str:
        messagebox.showerror("Errore", "Inserisci rete/CIDR e numero di host richiesti per sottorete.")
        return
    try:
        base_net = ipaddress.IPv4Network(net_str, strict=False)
    except Exception:
        messagebox.showerror("Errore", "Rete/CIDR non valida. Esempio valido: 192.168.1.0/24")
        return
    try:
        hosts_needed = int(hosts_str)
        if hosts_needed < 0:
            raise ValueError
    except Exception:
        messagebox.showerror("Errore", "Inserisci un numero di host valido (>=0).")
        return

    # Per ospitare H host servono almeno H+2 indirizzi (net + broadcast), tranne per /31 e /32 casi speciali
    required_addresses = hosts_needed + 2
    # trova il numero di bit per gli host
    host_bits = math.ceil(math.log2(required_addresses)) if required_addresses > 1 else 0
    new_prefix = 32 - host_bits
    if new_prefix < base_net.prefixlen:
        messagebox.showerror("Errore", f"Non è possibile ricavare sottoreti con {hosts_needed} host dalla rete {base_net}.")
        return

    # genera sottoreti con prefisso new_prefix fino a esaurire lo spazio
    subnets = list(base_net.subnets(new_prefix=new_prefix))
    if not subnets:
        messagebox.showerror("Errore", "Nessuna sottorete generata con i parametri forniti.")
        return

    txt_result_subnet.insert(tk.END, f"Da {base_net} -> sottoreti con prefisso /{new_prefix} (per ospitare ~{hosts_needed} host)\n\n")
    for i, s in enumerate(subnets, start=1):
        txt_result_subnet.insert(tk.END, f"Sottorete {i}:\n")
        txt_result_subnet.insert(tk.END, format_subnet_info(s))

def copia_risultati_subnet():
    testo = txt_result_subnet.get(1.0, tk.END).strip()
    if testo:
        copia_testo(testo)
    else:
        messagebox.showinfo("Info", "Nessun testo da copiare.")

def pulisci_subnet():
    entry_subnet_network.delete(0, tk.END)
    entry_subnet_n.delete(0, tk.END)
    entry_subnet_hosts.delete(0, tk.END)
    txt_result_subnet.delete(1.0, tk.END)

# -------------------- GUI principale --------------------
root = tk.Tk()
root.title("CONVERTITORE+")
root.geometry("780x720")
root.resizable(False, False)
# Se non hai icon.ico puoi commentare la prossima riga
try:
    root.iconbitmap("icon.ico")
except Exception:
    pass

sfondo = "#1e1e1e"; sfondo_frame = "#2d2d2d"; testo="#ffffff"; verde="#167913"
root.config(bg=sfondo)

style=ttk.Style(); style.theme_use("clam")
style.configure("TNotebook", background=sfondo, borderwidth=0)
style.configure("TNotebook.Tab", background=sfondo_frame, foreground=testo, padding=[20,10])
style.map("TNotebook.Tab", background=[("selected",verde)], foreground=[("selected","#000")])

notebook = ttk.Notebook(root); notebook.pack(expand=True, fill="both", pady=15, padx=15)

# -------------------- Funzione righe --------------------
def riga(label,var,frame):
    f = tk.Frame(frame, bg=sfondo); f.pack(pady=4, anchor="w")
    tk.Label(f,text=label,font=("Helvetica",13), fg=testo,bg=sfondo).pack(side=tk.LEFT,padx=10)
    tk.Label(f,textvariable=var,font=("Helvetica",13), fg=verde,bg=sfondo).pack(side=tk.LEFT,padx=10)
    tk.Button(f,text="Copia", command=lambda:copia_testo(var.get()),
              width=10, bg="#333", fg=testo, relief="flat", font=("Helvetica",10,"bold")).pack(side=tk.LEFT,padx=10)

# -------------------- Bottone standard --------------------
def bottone(master, text, command):
    return tk.Button(master, text=text, command=command,
                     font=("Helvetica",12,"bold"), bg=verde, fg="#000",
                     relief="flat", width=15, height=1, pady=5)

# -------------------- Scheda Sistemi Numerici --------------------
frame_num=tk.Frame(notebook,bg=sfondo); notebook.add(frame_num,text="Sistemi Numerici")
tk.Label(frame_num,text="Convertitore Base Numerica", font=("Helvetica",18,"bold"), fg=verde,bg=sfondo).pack(pady=15)
frame_input_num=tk.Frame(frame_num,bg=sfondo); frame_input_num.pack(pady=10)
tk.Label(frame_input_num,text="Numero:", font=("Helvetica",14), fg=testo,bg=sfondo).pack(side=tk.LEFT,padx=5)
entry_num=tk.Entry(frame_input_num,font=("Helvetica",14), width=20, justify="center",
                   bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_num.pack(side=tk.LEFT)
base_var=tk.StringVar(value="Decimale")
opt=tk.OptionMenu(frame_num, base_var, "Decimale","Binario","Ottale","Esadecimale")
opt.config(bg=sfondo_frame, fg=testo, font=("Helvetica",12), width=12)
opt["menu"].config(bg=sfondo_frame, fg=testo, font=("Helvetica",12))
opt.pack(pady=5)
bottone(frame_num,"Converti",converti_numero).pack(pady=3)
bottone(frame_num,"Pulisci",pulisci_num).pack(pady=3)
risultato_dec=tk.StringVar(); risultato_bin=tk.StringVar(); risultato_oct=tk.StringVar(); risultato_hex=tk.StringVar()
for lbl,var in zip(["Decimale:","Binario:","Ottale:","Esadecimale:"],[risultato_dec,risultato_bin,risultato_oct,risultato_hex]):
    riga(lbl,var,frame_num)

# -------------------- Scheda IPv4 --------------------
frame_ipv4=tk.Frame(notebook,bg=sfondo); notebook.add(frame_ipv4,text="IPv4")
tk.Label(frame_ipv4,text="Convertitore IPv4", font=("Helvetica",18,"bold"), fg=verde,bg=sfondo).pack(pady=15)
entry_ipv4=tk.Entry(frame_ipv4,font=("Helvetica",14), width=30, justify="center",
                    bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_ipv4.pack(pady=10)
bottone(frame_ipv4,"Decimale → Binario",ipv4_dec_bin).pack(pady=3)
bottone(frame_ipv4,"Binario → Decimale",ipv4_bin_dec).pack(pady=3)
bottone(frame_ipv4,"Pulisci",pulisci_ipv4).pack(pady=3)
risultato_ipv4=tk.StringVar()
tk.Label(frame_ipv4,text="Risultato:", font=("Helvetica",14,"bold"), fg=testo,bg=sfondo).pack(pady=5)
tk.Label(frame_ipv4,textvariable=risultato_ipv4,font=("Helvetica",14), fg=verde,bg=sfondo,wraplength=720).pack(pady=5)
tk.Button(frame_ipv4,text="Copia", command=lambda:copia_testo(risultato_ipv4.get()),
          width=10, bg="#333", fg=testo, relief="flat", font=("Helvetica",10,"bold")).pack(pady=3)

# -------------------- Scheda IPv6 --------------------
frame_ipv6=tk.Frame(notebook,bg=sfondo); notebook.add(frame_ipv6,text="IPv6")
tk.Label(frame_ipv6,text="Convertitore IPv6", font=("Helvetica",18,"bold"), fg=verde,bg=sfondo).pack(pady=15)
entry_ipv6=tk.Entry(frame_ipv6,font=("Helvetica",14), width=45, justify="center",
                    bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_ipv6.pack(pady=10)
bottone(frame_ipv6,"Esadecimale → Binario",ipv6_hex_bin).pack(pady=3)
bottone(frame_ipv6,"Binario → Esadecimale",ipv6_bin_hex).pack(pady=3)
bottone(frame_ipv6,"Pulisci",pulisci_ipv6).pack(pady=3)
risultato_ipv6=tk.StringVar()
tk.Label(frame_ipv6,text="Risultato:", font=("Helvetica",14,"bold"), fg=testo,bg=sfondo).pack(pady=5)
tk.Label(frame_ipv6,textvariable=risultato_ipv6,font=("Helvetica",12), fg=verde,bg=sfondo, wraplength=720, justify="center").pack(pady=5)
tk.Button(frame_ipv6,text="Copia", command=lambda:copia_testo(risultato_ipv6.get()),
          width=10, bg="#333", fg=testo, relief="flat", font=("Helvetica",10,"bold")).pack(pady=3)

# -------------------- Scheda Analisi IP Classful --------------------
frame_analizza=tk.Frame(notebook,bg=sfondo); notebook.add(frame_analizza,text="Analisi IP Classful")
tk.Label(frame_analizza,text="Analisi IPv4 Classful", font=("Helvetica",18,"bold"), fg=verde,bg=sfondo).pack(pady=15)
frame_input_analizza=tk.Frame(frame_analizza,bg=sfondo); frame_input_analizza.pack(pady=10)
tk.Label(frame_input_analizza,text="Indirizzo IPv4:", font=("Helvetica",14), fg=testo,bg=sfondo).pack(side=tk.LEFT,padx=5)
entry_ip_analizza=tk.Entry(frame_input_analizza,font=("Helvetica",14), width=25, justify="center",
                           bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_ip_analizza.pack(side=tk.LEFT)
bottone(frame_analizza,"Analizza",analizza_ip_gui).pack(pady=3)
bottone(frame_analizza,"Pulisci",pulisci_ip_analizza).pack(pady=3)
classe_var=tk.StringVar(); subnet_var=tk.StringVar(); rete_var=tk.StringVar()
broadcast_var=tk.StringVar(); range_var=tk.StringVar(); numero_var=tk.IntVar(); tipo_var=tk.StringVar()
for lbl,var in zip(["Classe:","Subnet Mask:","Rete:","Broadcast:","Range Host:","Numero Host:","Tipo:"],
                   [classe_var,subnet_var,rete_var,broadcast_var,range_var,numero_var,tipo_var]):
    riga(lbl,var,frame_analizza)

# -------------------- Scheda Analisi IP Classless --------------------
frame_classless=tk.Frame(notebook,bg=sfondo); notebook.add(frame_classless,text="Analisi IP Classless")
tk.Label(frame_classless,text="Analisi IPv4 Classless (CIDR)", font=("Helvetica",18,"bold"), fg=verde,bg=sfondo).pack(pady=15)
frame_input_cless=tk.Frame(frame_classless,bg=sfondo); frame_input_cless.pack(pady=10)
tk.Label(frame_input_cless,text="Indirizzo IPv4/CIDR:", font=("Helvetica",14), fg=testo,bg=sfondo).pack(side=tk.LEFT,padx=5)
entry_ip_classless=tk.Entry(frame_input_cless,font=("Helvetica",14), width=25, justify="center",
                            bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_ip_classless.pack(side=tk.LEFT)
bottone(frame_classless,"Analizza",analizza_ip_classless_gui).pack(pady=3)
bottone(frame_classless,"Pulisci",pulisci_ip_classless).pack(pady=3)
cless_mask_var=tk.StringVar(); cless_rete_var=tk.StringVar(); cless_broadcast_var=tk.StringVar()
cless_range_var=tk.StringVar(); cless_num_var=tk.IntVar(); cless_tipo_var=tk.StringVar()
for lbl,var in zip(["Subnet Prefix:","Rete:","Broadcast:","Range Host:","Numero Host:","Tipo:"],
                   [cless_mask_var,cless_rete_var,cless_broadcast_var,cless_range_var,cless_num_var,cless_tipo_var]):
    riga(lbl,var,frame_classless)

# -------------------- Scheda Subnetting (NUOVA) --------------------
frame_subnet=tk.Frame(notebook,bg=sfondo); notebook.add(frame_subnet,text="Subnetting")
tk.Label(frame_subnet,text="Subnetting - Divisione in sottoreti", font=("Helvetica",18,"bold"), fg=verde,bg=sfondo).pack(pady=12)

frame_sub_input = tk.Frame(frame_subnet, bg=sfondo); frame_sub_input.pack(pady=6)
tk.Label(frame_sub_input, text="Rete/CIDR:", font=("Helvetica",13), fg=testo, bg=sfondo).grid(row=0, column=0, padx=6, pady=4, sticky="e")
entry_subnet_network = tk.Entry(frame_sub_input, font=("Helvetica",13), width=28, justify="center",
                                bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_subnet_network.grid(row=0, column=1, padx=6, pady=4, sticky="w")
tk.Label(frame_sub_input, text="Dividi in N sottoreti:", font=("Helvetica",12), fg=testo, bg=sfondo).grid(row=1, column=0, padx=6, pady=4, sticky="e")
entry_subnet_n = tk.Entry(frame_sub_input, font=("Helvetica",12), width=12, justify="center",
                          bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_subnet_n.grid(row=1, column=1, padx=6, pady=4, sticky="w")
tk.Label(frame_sub_input, text="Host req. per sottorete:", font=("Helvetica",12), fg=testo, bg=sfondo).grid(row=2, column=0, padx=6, pady=4, sticky="e")
entry_subnet_hosts = tk.Entry(frame_sub_input, font=("Helvetica",12), width=12, justify="center",
                              bg=sfondo_frame, fg=testo, insertbackground=testo)
entry_subnet_hosts.grid(row=2, column=1, padx=6, pady=4, sticky="w")

btn_frame_sub = tk.Frame(frame_subnet, bg=sfondo); btn_frame_sub.pack(pady=6)
tk.Button(btn_frame_sub, text="Dividi in N sottoreti", command=subnet_dividi_equal,
          font=("Helvetica",12,"bold"), bg=verde, fg="#000", relief="flat", width=20).pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame_sub, text="Sottoreti per X host", command=subnet_dividi_by_hosts,
          font=("Helvetica",12,"bold"), bg=verde, fg="#000", relief="flat", width=20).pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame_sub, text="Pulisci", command=pulisci_subnet,
          font=("Helvetica",12,"bold"), bg="#333", fg=testo, relief="flat", width=12).pack(side=tk.LEFT, padx=6)

# area risultati scorrevole
frame_result_sub = tk.Frame(frame_subnet, bg=sfondo); frame_result_sub.pack(pady=8, fill="both", expand=True)
txt_result_subnet = scrolledtext.ScrolledText(frame_result_sub, wrap=tk.WORD, font=("Consolas",11),
                                              bg="#111", fg=verde, insertbackground=testo, width=80, height=18)
txt_result_subnet.pack(padx=10, pady=6, fill="both", expand=True)
tk.Button(frame_subnet, text="Copia risultati", command=copia_risultati_subnet,
          width=14, bg="#333", fg=testo, relief="flat", font=("Helvetica",10,"bold")).pack(pady=6)

# -------------------- Scheda Info --------------------
frame_info=tk.Frame(notebook,bg=sfondo); notebook.add(frame_info,text="Info")
tk.Label(frame_info,text="CONVERTITORE+", font=("Helvetica",20,"bold"), fg=verde,bg=sfondo).pack(pady=20)
tk.Label(frame_info,text=(
    "Questa applicazione converte numeri tra sistemi numerici (Dec, Bin, Oct, Hex) e gestisce IPv4/IPv6.\n"
    "Include l'analisi Classful e Classless degli IP e la funzione di Subnetting.\n\n"
    "Sviluppata in Python + Tkinter.\n\n"
    "Credits: Diego Valle\nVersione: 0.2 (integrazione Subnetting)"
), font=("Helvetica",12), fg=testo,bg=sfondo, justify="center").pack(pady=20)

# -------------------- Avvio --------------------
root.mainloop()
