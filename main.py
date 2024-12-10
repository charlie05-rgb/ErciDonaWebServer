import sqlite3
import ssl

from dotenv import load_dotenv
import os
import jwt

from flask import Flask, render_template, request, make_response, redirect, jsonify

from ddbb import get_db_connection



app = Flask(__name__)
conexion =None
tunel = None

# Función para generar token
def generate_token(userlogin):
    # Codifica el token JWT con el nombre de usuario y la clave secreta
    token = jwt.encode({'userlogin': userlogin}, os.getenv('SECRET_KEY'), algorithm='HS512')
    return token

# Función para verificar token
def verify_token(token, userlogin):
    try:
        # Verifica la firma del token JWT utilizando la clave secreta
        decoded_token = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=['HS512'])

        # Verificar si el nombre de usuario del token coincide con el usuario proporcionado
        if decoded_token['userlogin'] == userlogin:
            return True
    except jwt.ExpiredSignatureError:
        # Manejar el caso en que el token ha expirado
        return None
    except jwt.InvalidTokenError:
        # Manejar el caso en que el token es inválido
        return None


#Son las dirferentes rutas que hay dentro de la web
#ruta a la que se hace referencia, en este caso la dirección

@app.route('/')
def home():
 return render_template('login_template.html')

@app.route('/read_qr')
def read_qr():
    return render_template('read_qr.html')


@app.route('/qr_ok')
def qr_ok():
    return render_template('qr_ok.html')

@app.route('/qr_fail')
def qr_fail():
    return render_template('qr_fail.html')


@app.route('/qr-data', methods=['POST'])
def qr_data():
    if request.is_json:
        qr_content = request.json.get('qr_data')
        print("Contenido del QR:", qr_content)

        # Responder con JSON indicando éxito y redirigir en el cliente
        return jsonify({"message": "QR recibido", "content": "qr_fail"})

    else:
        return jsonify({"error": "No se recibió JSON válido"}), 400


@app.route('/sign_in', methods=['POST'])
def sign_in():
    # Obtener los datos del formulario
    login = request.form['correo']
    passwd = request.form['passwd']

    try:
        # Obtener un cursor de la conexión
        cursor = conexion.cursor()

        # Llamar al procedimiento almacenado 'login_usuario'
        #Es el cursor de la base de datos
        cursor.callproc('login_usuario', (login, passwd))

        # Obtener el valor de retorno del procedimiento (booleano)
        result = cursor.fetchone()  # Debería devolver (True,) o (False,)
        if result and result[0]:
            print("Login exitoso.")
            # Generar un token JWT utilizando el nombre de usuario
            token = generate_token(login) #Genera un token con el nombre o correo

            # Crear la respuesta
            response = make_response(redirect('/login_ok'))  # Redirigir a login_o

            # Establecer una cookie en la respuesta con el token JWT
            response.set_cookie('token', token)
            response.set_cookie('userlogin', login)

            # Devolver la respuesta con la cookie establecida
            return response

        else:
            print("Credenciales incorrectas.")
            return render_template('login_incorrecto_template.html')

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error al verificar las credenciales.'

    finally:
        cursor.close()


# Ejemplo de una ruta protegida
@app.route('/login_ok')
def login_ok():
    # Obtener el token y el nombre de usuario desde las cookies de la solicitud
    token = request.cookies.get('token')         # Obtener el token JWT de la cookie
    userlogin = request.cookies.get('userlogin') # Obtener el nombre de usuario de la cookie

    # Verificar si el token o el nombre de usuario están ausentes
    if not token or not userlogin:
        # Si faltan el token o el nombre de usuario, renderizar una plantilla de error de token
        return render_template('token_fail.html')

    # Verificar la validez del token
    decoded_token = verify_token(token, userlogin)

    # Verificar si el token es válido
    if decoded_token:
        # Si el token es válido, renderizar la plantilla para la ruta protegida
        return render_template('login_ok_template.html')
    else:
        # Si el token no es válido, renderizar una plantilla de error de token
        return render_template('token_fail.html')


@app.route('/registro_usuario')
def form_registro():
 return render_template('register_usuario.html')


@app.route('/register_user', methods=['POST'])
def register_user():
    nombre = request.form['nombreusu']
    mail = request.form['correo']
    passwd = request.form['contrasenausu']
    telefono = request.form['numerotelefono']
    direccion = request.form['direccionusu']

    try:
        # Obtener un cursor de la conexión
        cursor = conexion.cursor()

        # Llamar al procedimiento almacenado 'login_usuario'
        cursor.callproc('registrar_usuario', (nombre, mail, passwd, direccion, telefono))

        # Obtener el valor de retorno del procedimiento (booleano)
        result = cursor.fetchone()  # Debería devolver (True,) o (False,)

        conexion.commit()

        if result and result[0]:
            print("Registro exitoso.")
            # Generar un token JWT utilizando el nombre de usuario

            return render_template('autentication.html')

        else:
            print("Credenciales incorrectas.")
            return render_template('login_incorrecto_template.html')

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error al verificar las credenciales.'

    finally:
        cursor.close()



@app.route('/autenticar_usuario_fail')
def form_autenticar_fail():
    return (render_template('autentication_fail.html'))


@app.route('/autenticar_usuario')
def form_autenticar():
    return (render_template('autentication.html'))



@app.route('/autentication_user', methods=['POST'])
def form_autentication():
    nombre = request.form['nombre_user']
    codigo = request.form['codigo_user']

    try:
        cursor = conexion.cursor()
        cursor.callproc('verificar_usuario', (nombre, codigo))
        result = cursor.fetchone()
        conexion.commit()

        if result and result[0]:
            print("Autenticacion exitoso.")
            return  render_template('autentication_ok.html')

        else:
            print("Codigo incorrecto")
            return render_template('autentication_fail.html')

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error al verificar las credenciales.'

    finally:
        cursor.close()





#Donde empieza la aplicación
if __name__ == '__main__':
    conexion , tunel = get_db_connection()
    #app.run(app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000, debug=True))
    # app.run(app.run(host='0.0.0.0', port=5000, debug=True))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/root/home/certs/cerciapps_sytes_net.pem', '/root/home/certs/erciapps.key')
    app.run(ssl_context=context, host='0.0.0.0', port=5001, debug=True)
