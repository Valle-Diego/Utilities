from flask import Flask, render_template, request

app = Flask(__name__)

# Funzione MCD (iterativa)
def mcd_iter(a, b):
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a

# Funzione MCD (ricorsiva)
def mcd_rec(a, b):
    a, b = abs(a), abs(b)
    if b == 0:
        return a
    return mcd_rec(b, a % b)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    if request.method == 'POST':
        try:
            a = int(request.form['a'])
            b = int(request.form['b'])
            method = request.form['method']
            
            # Riordino automatico
            if a < b:
                a, b = b, a

            if a == 0 and b == 0:
                error = "Errore: il MCD non è definito per entrambi i numeri 0."
            else:
                if method == 'ricorsivo':
                    result = mcd_rec(a, b)
                else:
                    result = mcd_iter(a, b)
        except ValueError:
            error = "Inserisci numeri validi."
    return render_template('index.html', result=result, error=error)

if __name__ == '__main__':
    app.run(debug=True)
