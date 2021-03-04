import json
import os
import aurora_data_api
from chalice import Chalice, BadRequestError, ChaliceViewError, CognitoUserPoolAuthorizer, UnauthorizedError
from cognitojwt import CognitoJWTException
from pycognito import Cognito
import cognitojwt
import urllib.request

region = os.environ['REGION']
user_pool_id = os.environ['COGNITO_USER_POOL_ID']
client_id = os.environ['COGNITO_CLIENT_ID']
client_secret = os.environ['COGNITO_CLIENT_SECRET']
db_cluster_arn = os.environ['DB_CLUSTER_ARN']
db_credentials_secret_arn = os.environ['DB_CREDENTIALS_SECRET_ARN']
db_name = os.environ['DB_NAME']
db_citizen_role_id = os.environ['DB_CITIZEN_ROL']
u = Cognito(user_pool_id, client_id, client_secret=client_secret)
authorizer = CognitoUserPoolAuthorizer(os.environ['COGNITO_USER_POOL'],
                                       provider_arns=[os.environ['COGNITO_USER_POOL_ARN']])
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, user_pool_id)
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

app = Chalice(app_name=os.environ['API_NAME'])
app.api.cors = True


@app.route('/admin/usuarios', methods=['GET'], authorizer=authorizer)
def get_admin_users():
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/admin/usuarios'
    try:
        if check_user_access(id_token, resource):
            users = u.get_users()
            users_list = []
            for item in users:
                users_list.append(item.__dict__.get('_data')['email'])
            return json.dumps(get_users_db(users_list))
        else:
            raise UnauthorizedError("El usuario no tiene acceso al recurso")
    except CognitoJWTException as e:
        raise UnauthorizedError("Token expirado")


@app.route('/admin/usuarios/{email}', methods=['GET'], authorizer=authorizer)
def get_admin_user(email):
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/admin/usuarios'
    try:
        if email:
            if check_user_access(id_token, resource):
                try:
                    u.username = email
                    user = u.admin_get_user().__dict__.get('_data')
                    userdb = get_user_profile_db(email)
                    return json.dumps({**user, **userdb})
                except Exception as e:
                    print(e)
                    return {
                        "status": "error",
                        "message": "El usuario no existe"
                    }
            else:
                raise UnauthorizedError("El usuario no tiene acceso al recurso")
        else:
            raise BadRequestError("El campo correo es obligatorio")
    except CognitoJWTException as e:
        raise UnauthorizedError("Token expirado")


@app.route('/usuarios', methods=['GET'], authorizer=authorizer)
def get_user():
    id_token = app.current_request.headers["Authorization"][7:]
    try:
        email = get_token_claims(id_token)['email']
        u.username = email
        user = u.admin_get_user().__dict__.get('_data')
        userdb = get_user_profile_db(email)
        return json.dumps({**user, **userdb})
    except CognitoJWTException as e:
        raise UnauthorizedError("Token expirado")
    except Exception as e:
        return {
            "status": "error",
            "message": "El usuario no existe"
        }


def check_user_exist(email):
    try:
        u.username = email
        u.admin_get_user()
        return True
    except Exception as e:
        return False


@app.route('/admin/usuarios', methods=['POST'], authorizer=authorizer)
def create_user():
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/admin/usuarios'
    try:
        if check_user_access(id_token, resource):
            body = app.current_request.json_body
            if all(k in body for k in ('correo', 'password', 'nombres', 'apellidos', 'id_municipio', 'id_rol')):
                if check_user_exist(body['correo']):
                    raise BadRequestError("El usuario ya existe")
                else:
                    u.username = body['correo']
                    u.set_base_attributes(email=body['correo'])
                    user = u.register(body['correo'], body['password'])
                    try:
                        create_user_db(body)
                    except Exception as e:
                        delete_user_cognito(body['correo'])
                        print(e)
                        raise ChaliceViewError("Ocurrio un error al crear el usuario")
                    return {
                        "status": "success",
                        "message": "Usuario creado"
                    }
            else:
                raise BadRequestError("Campos obligatorios incompletos")
        else:
            raise UnauthorizedError("El usuario no tiene acceso al recurso")
    except CognitoJWTException as e:
        raise UnauthorizedError("Token expirado")


@app.route('/admin/usuarios', methods=['PUT'], authorizer=authorizer)
def update_user():
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/admin/usuarios'
    try:
        if check_user_access(id_token, resource):
            body = app.current_request.json_body
            if 'correo' in body:
                if not check_user_exist(body['correo']):
                    raise BadRequestError("El usuario no existe")
                else:
                    try:
                        update_user_db(body)
                    except Exception as e:
                        print(e)
                        raise ChaliceViewError("Ocurrio un error al actualizar el usuario")
                    return {
                        "status": "success",
                        "message": "Usuario actualizado"
                    }
            else:
                raise BadRequestError("El campo correo es obligatorio")
        else:
            raise UnauthorizedError("El usuario no tiene acceso al recurso")
    except CognitoJWTException as e:
        raise UnauthorizedError("Token expirado")


@app.route('/admin/usuarios/{email}', methods=['DELETE'], authorizer=authorizer)
def delete_user(email):
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/admin/usuarios'
    try:
        if check_user_access(id_token, resource):
            if email:
                if not check_user_exist(email):
                    raise BadRequestError("El usuario no existe")
                else:
                    try:
                        delete_user_cognito(email)
                        delete_user_db(email)
                    except Exception as e:
                        print(e)
                        raise ChaliceViewError("Ocurrio un error al eliminar el usuario")
                    return {
                        "status": "success",
                        "message": "Usuario eliminado"
                    }
            else:
                raise BadRequestError("El campo correo es obligatorio")
        else:
            raise UnauthorizedError("El usuario no tiene acceso al recurso")
    except CognitoJWTException as e:
        raise UnauthorizedError("Token expirado")


@app.route('/usuarios/registro', methods=['POST'])
def register_user():
    body = app.current_request.json_body
    if all(k in body for k in ('correo', 'nombres', 'apellidos', 'id_municipio', 'id_terminos')):
        if check_user_exist(body['correo']):
            raise BadRequestError("El usuario ya existe")
        else:
            u.username = body['correo']
            u.set_base_attributes(email=body['correo'])
            user = u.register(body['correo'], body['password'] if 'password' in body else 'TempPassword2021')
            body['id_rol'] = db_citizen_role_id
            try:
                create_user_db(body)
            except Exception as e:
                delete_user_cognito(body['correo'])
                print(e)
                raise ChaliceViewError("Ocurrio un error al registrar el usuario")
            return {
                "status": "success",
                "message": "Registro exitoso"
            }
    else:
        raise BadRequestError("Campos obligatorios incompletos")


@app.route('/usuarios/login', methods=['POST'])
def login_user():
    body = app.current_request.json_body
    if all(k in body for k in ('correo', 'password')):
        try:
            u.username = body['correo']
            u.authenticate(password=body['password'])
            user = get_user_profile_db(body['correo'])
            return {
                "correo": u.username,
                "token_type": u.token_type,
                "access_token": u.access_token,
                "refresh_token": u.refresh_token,
                "id_token": u.id_token,
                "user_data": user
            }
        except Exception as e:
            print(e)
            if "NotAuthorizedException" in str(e):
                return {
                    "status": "error",
                    "message": "Usuario o contraseña incorrecta"
                }
            else:
                raise ChaliceViewError("Ocurrio un error al autenticar el usuario ")
    else:
        raise BadRequestError("Campos obligatorios incompletos")


@app.route('/usuarios/logout', methods=['POST'], authorizer=authorizer)
def logout_user():
    body = app.current_request.json_body
    if 'access_token' in body:
        try:
            u.access_token = body['access_token']
            u.logout()
            return {
                "status": "success",
                "message": "Logout exitoso"
            }
        except Exception as e:
            print(e)
            raise ChaliceViewError("Ocurrio un error al hacer logout")
    else:
        raise BadRequestError("Campos obligatorios incompletos")


def create_user_db(user):
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO USUARIO (correo, nombres, apellidos, tipo_documento, 
                           numero_documento, celular, id_municipio, id_rol, id_terminos) 
                           VALUES (:correo, :nombres, :apellidos, :tipo_documento, 
                           :numero_documento, :celular, :id_municipio, :id_rol, :id_terminos)
                """,
                           {
                               "correo": user["correo"],
                               "nombres": user["nombres"],
                               "apellidos": user["apellidos"],
                               "tipo_documento": user["tipo_documento"] if "tipo_documento" in user else "",
                               "numero_documento": user[
                                   "numero_documento"] if "numero_documento" in user else "",
                               "celular": user["celular"] if "celular" in user else "",
                               "id_municipio": user["id_municipio"],
                               "id_rol": user["id_rol"],
                               "id_terminos": user["id_terminos"] if "id_terminos" in user else None
                           }
                           )


def update_user_db(user):
    params = user.copy()
    del params['correo']
    sql = "UPDATE USUARIO SET "
    for k, v in params.items():
        sql += "%s = %s, " % (k, ":"+k)
    sql = sql[:-2] + " WHERE correo = :correo"
    params.update(correo=user['correo'])
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)


def delete_user_db(email):
    sql = "DELETE FROM USUARIO WHERE correo = :email"
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, {"email": email})


def delete_user_cognito(email):
    try:
        u.username = email
        u.admin_delete_user()
    except Exception as e:
        return {
            "status": "error",
            "message": "El usuario no existe"
        }


def get_users_db(email_list):
    format_list = ''
    users_list = []
    for i in range(0, len(email_list)):
        format_list += ',:' + str(i)
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
            SELECT u.correo, u.nombres, u.apellidos, u.tipo_documento, 
            u.numero_documento, u.celular
            FROM USUARIO u
            WHERE u.correo in (%s)
            """ % format_list[1:], {str(i): email_list[i] for i in range(0, len(email_list))})
            for reg in cursor:
                user = {}
                user.update(correo=reg[0])
                user.update(nombres=reg[1])
                user.update(apellidos=reg[2])
                user.update(tipo_documento=reg[3])
                user.update(numero_documento=reg[4])
                user.update(celular=reg[5])
                users_list.append(user)
            return users_list


def get_user_profile_db(email):
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
            SELECT u.correo, u.nombres, u.apellidos, u.tipo_documento, 
            u.numero_documento, u.celular, r.id AS id_rol, r.nombre AS rol, 
            m.id AS id_municipio, m.nombre AS municipio, m.logo, m.slogan, re.path
            FROM USUARIO u, ROL r, MUNICIPIO m, ROL_RECURSO rr, RECURSO re
            WHERE u.id_rol = r.id AND u.id_municipio = m.id 
            AND u.id_rol = rr.id_rol AND rr.id_recurso = re.id
            AND u.correo = :email
            """, {"email": email})
            user = {}
            resources = []
            for reg in cursor:
                user.update(correo=reg[0])
                user.update(nombres=reg[1])
                user.update(apellidos=reg[2])
                user.update(tipo_documento=reg[3])
                user.update(numero_documento=reg[4])
                user.update(celular=reg[5])
                user.update(id_rol=reg[6])
                user.update(rol=reg[7])
                user.update(id_municipio=reg[8])
                user.update(municipio=reg[9])
                user.update(logo=reg[10])
                user.update(slogan=reg[11])
                resources.append(reg[12])
                user.update(resources=resources)
            return user


def check_user_access(id_token, resource):
    user_claims = get_token_claims(id_token)
    if user_claims:
        email = user_claims.get('email')
        with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                     database=db_name) as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                SELECT re.nombre AS recurso, re.path
                FROM USUARIO u, ROL r, ROL_RECURSO rr, RECURSO re
                WHERE rr.id_rol = r.id AND rr.id_recurso = re.id
                AND u.id_rol = r.id
                AND u.correo = :email and re.path = :resource
                """, {
                    "email": email,
                    "resource": resource
                })
                if cursor.rowcount > 0:
                    return True
                else:
                    return False
    else:
        return False


def get_token_claims(id_token):
    verified_claims: dict = cognitojwt.decode(
        id_token,
        region,
        user_pool_id
    )
    return verified_claims
