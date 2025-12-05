# app.py
from flask import Flask, render_template, request

app = Flask(__name__)

# Algoritmo Euclideo Esteso per l'inverso modulare
def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % phi

def rsa_generate(p, q, e):
    N = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return (e, N), (d, N)

def rsa_encrypt(M, e, N):
    return pow(M, e, N)

def rsa_decrypt(C, d, N):
    return pow(C, d, N)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        try:
            p = int(request.form['p'])
            q = int(request.form['q'])
            e = int(request.form['e'])
            M = int(request.form['M'])

            pubblica, privata = rsa_generate(p, q, e)
            C = rsa_encrypt(M, pubblica[0], pubblica[1])
            M_dec = rsa_decrypt(C, privata[0], privata[1])

            result = {
                'pub_key': pubblica,
                'priv_key': privata,
                'cipher': C,
                'decipher': M_dec
            }
        except Exception as err:
            result = {'error': str(err)}

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
