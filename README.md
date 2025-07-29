Realizado por: Anthony Javier Zambrano Alcivar 6to Semestre

# 🔐 Aplicación Flask con Autenticación Segura

## 🎯 Objetivo

Desarrollar una aplicación web con Flask que implemente un sistema de autenticación seguro. El sistema debe estar protegido contra inyecciones SQL, ataques XSS y gestionar sesiones de forma segura.

---

## ✅ Funcionalidades implementadas

- 📋 Registro de usuarios (nombre, correo, contraseña).
- 🔑 Inicio de sesión con validación de credenciales.
- 🔒 Página protegida accesible solo para usuarios autenticados.
- 🚪 Cierre de sesión.

---

## 🛡️ Medidas de Seguridad Implementadas

### 1. 🧾 **Consultas Parametrizadas (contra Inyección SQL)**

Todas las operaciones con la base de datos usan parámetros `?` para evitar que entradas del usuario sean interpretadas como comandos SQL.

```python
conn.execute("SELECT * FROM users WHERE email = ?", (email,))

2. 🧼 Protección contra XSS (Cross-Site Scripting)
Se usa la librería bleach para sanitizar las entradas del formulario antes de almacenarlas o mostrarlas.

Código python

name = bleach.clean(request.form["name"])
email = bleach.clean(request.form["email"])
✅ Esto evita que un usuario malicioso ejecute código JavaScript como <script>alert("XSS")</script>.

3. 🔒 Contraseñas con Hash (Werkzeug)
Las contraseñas se almacenan de forma segura usando hashing con generate_password_hash() y se comparan con check_password_hash().

Código python

hashed_password = generate_password_hash(password)
✅ Esto evita que las contraseñas reales queden expuestas en la base de datos.

4. 🔐 Gestión segura de sesiones (Flask-Session)
Se configura Flask-Session para guardar sesiones del lado del servidor.

Código python

app.config["SESSION_TYPE"] = "filesystem"
Session(app)
✅ Esto impide que la sesión del usuario se guarde solo en cookies, mejorando la protección contra manipulación del lado cliente.

🗂️ Estructura del Proyecto
csharp
Copiar
Editar
flask_auth_app/
│
├── app.py              # Código principal de Flask
├── users.db            # Base de datos SQLite
├── README.md           # Este archivo
├── templates/
│   ├── register.html   # Formulario de registro
│   ├── login.html      # Formulario de inicio de sesión
│   └── protected.html  # Página protegida
├── static/             # (vacío o para CSS, imágenes, etc.)

▶️ Cómo ejecutar el proyecto
Clona el repositorio o descarga el proyecto:

git clone https://github.com/usuario/flask_auth_app.git
cd flask_auth_app


Crea y activa un entorno virtual:

python -m venv venv
venv\Scripts\activate  # En Windows
source venv/bin/activate  # En Linux/Mac


Instala las dependencias:
pip install flask flask-session bleach werkzeug


Ejecuta la aplicación:
python app.py


Abre en el navegador:
http://127.0.0.1:5000



📚 Bibliografía
OWASP. (2021). OWASP Top Ten. https://owasp.org/www-project-top-ten/

Flask Docs: https://flask.palletsprojects.com/

Flask-Session: https://flask-session.readthedocs.io/

Werkzeug: https://werkzeug.palletsprojects.com/

Bleach: https://bleach.readthedocs.io/

