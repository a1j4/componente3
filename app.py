from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import re
import bleach
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.secret_key = "clave_segura"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

def validar_nombre(nombre):
    patron = re.compile(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s\-]+$")
    return bool(patron.fullmatch(nombre))

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        raw_name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        errores = {}

        if not all([raw_name, email, password]):
            errores["generico"] = "Todos los campos son obligatorios"

        if not validar_nombre(raw_name):
            errores["nombre"] = "El nombre contiene caracteres no permitidos"

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            errores["correo"] = "Correo inválido: " + str(e)

        if len(password) < 8:
            errores["contrasena"] = "La contraseña debe tener al menos 8 caracteres"

        if errores:
            return render_template("register.html", errores=errores,
                                   nombre=raw_name, correo=email)

        name = bleach.clean(raw_name)
        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect("users.db") as conn:
                conn.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, hashed_password)
                )
                conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            errores["correo"] = "El correo ya está registrado"
            return render_template("register.html", errores=errores,
                                   nombre=raw_name, correo=email)

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = bleach.clean(request.form["email"])
        password = request.form["password"]

        with sqlite3.connect("users.db") as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            return redirect(url_for("protected"))
        else:
            errores = {"login": "Correo o contraseña incorrectos"}
            return render_template("login.html", errores=errores, correo=email)

    return render_template("login.html")

@app.route("/protected")
def protected():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("protected.html", name=session["user_name"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
