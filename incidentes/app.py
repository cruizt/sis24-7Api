from chalice import Chalice, BadRequestError, ChaliceViewError, CognitoUserPoolAuthorizer, UnauthorizedError
import os
import cognitojwt
import aurora_data_api

region = os.environ['REGION']
user_pool_id = os.environ['COGNITO_USER_POOL_ID']
db_name = os.environ['DB_NAME']
db_citizen_role_id = os.environ['DB_CITIZEN_ROL']
db_cluster_arn = os.environ['DB_CLUSTER_ARN']
db_credentials_secret_arn = os.environ['DB_CREDENTIALS_SECRET_ARN']
authorizer = CognitoUserPoolAuthorizer(os.environ['COGNITO_USER_POOL'],
                                       provider_arns=[os.environ['COGNITO_USER_POOL_ARN']])

app = Chalice(app_name=os.environ['API_NAME'])
app.api.cors = True

@app.route('/listas/{tipo_lista}', methods=['GET'])
def get_list(tipo_lista):
    if tipo_lista in ['municipios', 'incidentes', 'terminos', 'roles']:
        return get_list_db(tipo_lista)
    else:
        raise BadRequestError("El tipo " + tipo_lista + " no es una lista válida")


@app.route('/incidentes', methods=['POST'], authorizer=authorizer)
def create_incident():
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/incidentes'
    if check_user_access(id_token, resource):
        body = app.current_request.json_body
        if all(k in body for k in ('hechos', 'ubicacion', 'fecha', 'id_tipo_incidente', 'id_municipio')):
            try:
                id_incident = create_incident_db(body)
            except Exception as e:
                print(e)
                raise ChaliceViewError("Ocurrio un error al crear el incidente")
            return {
                "status": "success",
                "message": "Incidente creado",
                "data": {
                    "id_incidente": id_incident
                }
            }
        else:
            raise BadRequestError("Campos obligatorios incompletos")
    else:
        raise UnauthorizedError("El usuario no tiene acceso al recurso")


@app.route('/admin/incidentes', methods=['GET'],
           authorizer=authorizer)
def get_incidents():
    id_token = app.current_request.headers["Authorization"][7:]
    resource = app.current_request.method + '/admin/incidentes'
    if check_user_access(id_token, resource):
        query_params = app.current_request.query_params
        if all(k in query_params for k in ('fecha_inicial', 'fecha_final', 'id_municipio')):
            return get_incidents_db(query_params['fecha_inicial'], query_params['fecha_final'], query_params['id_municipio'],
                                    query_params['id_tipo_incidente'] if 'id_tipo_incidente' in query_params else None)
        else:
            raise BadRequestError("Campos obligatorios incompletos")
    else:
        raise UnauthorizedError("El usuario no tiene acceso al recurso")


def get_list_db(list_type):
    list = []
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            if list_type == 'municipios':
                cursor.execute("""
                SELECT id, nombre, logo, slogan, coordenadas
                FROM MUNICIPIO
                """)
                for reg in cursor:
                    municipio = {}
                    municipio.update(id=reg[0])
                    municipio.update(nombre=reg[1])
                    municipio.update(logo=reg[2])
                    municipio.update(slogan=reg[3])
                    municipio.update(coordenadas=reg[4])
                    list.append(municipio)
            elif list_type == 'incidentes':
                cursor.execute("""
                SELECT id, descripcion, icono
                FROM TIPO_INCIDENTE
                """)
                for reg in cursor:
                    tipo_incidente = {}
                    tipo_incidente.update(id=reg[0])
                    tipo_incidente.update(descripcion=reg[1])
                    tipo_incidente.update(icono=reg[2])
                    list.append(tipo_incidente)
            elif list_type == 'terminos':
                cursor.execute("""
                                SELECT id, texto_legal, version
                                FROM TERMINOS_CONDICIONES ORDER BY id DESC LIMIT 1
                                """)
                for reg in cursor:
                    tipo_terminos = {}
                    tipo_terminos.update(id=reg[0])
                    tipo_terminos.update(texto_legal=reg[1])
                    tipo_terminos.update(version=reg[2])
                return tipo_terminos
            elif list_type == 'roles':
                cursor.execute("""
                                SELECT id, nombre
                                FROM ROL
                                """)
                for reg in cursor:
                    tipo_rol = {}
                    tipo_rol.update(id=reg[0])
                    tipo_rol.update(nombre=reg[1])
                    list.append(tipo_rol)
            return list


def create_incident_db(incident):
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        with conn.cursor() as cursor:
            id_usuario = None
            if 'correo_usuario' in incident:
                cursor.execute("""
                                SELECT id
                                FROM USUARIO
                                WHERE correo = :email
                                """, {
                    "email": incident['correo_usuario']
                })
                for reg in cursor:
                    id_usuario = reg[0]

            cursor.execute("""
                INSERT INTO INCIDENTE (hechos, ubicacion, fecha, id_tipo_incidente, 
                           id_municipio, id_usuario) 
                           VALUES (:hechos, :ubicacion, :fecha, :id_tipo_incidente, 
                           :id_municipio, :id_usuario)
                """,
                           {
                               "hechos": incident["hechos"],
                               "ubicacion": incident["ubicacion"],
                               "fecha": incident["fecha"],
                               "id_tipo_incidente": incident["id_tipo_incidente"],
                               "id_municipio": incident["id_municipio"],
                               "id_usuario": id_usuario
                           }
                           )
            return cursor.lastrowid


def get_incidents_db(fecha_inicial, fecha_final, id_municipio, id_tipo_inicidente):
    with aurora_data_api.connect(aurora_cluster_arn=db_cluster_arn, secret_arn=db_credentials_secret_arn,
                                 database=db_name) as conn:
        query = """
            SELECT i.id, i.hechos, i.ubicacion, i.fecha, i.id_tipo_incidente, ti.descripcion, i.id_municipio, m.nombre
            FROM INCIDENTE i, MUNICIPIO m, TIPO_INCIDENTE ti
            WHERE i.id_municipio = m.id AND i.id_tipo_incidente = ti.id
            AND DATE(i.fecha) BETWEEN STR_TO_DATE(:fecha_inicial,'%Y-%m-%d') AND STR_TO_DATE(:fecha_final,'%Y-%m-%d')
            AND i.id_municipio = :id_municipio
            """
        params = {
            "fecha_inicial": fecha_inicial,
            "fecha_final": fecha_final,
            "id_municipio": id_municipio
        }
        incident_list = []
        if id_tipo_inicidente:
            query += " AND i.id_tipo_incidente = :id_tipo_incidente"
            params.update(id_tipo_incidente=id_tipo_inicidente)
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            for reg in cursor:
                incident = {}
                incident.update(id=reg[0])
                incident.update(hechos=reg[1])
                incident.update(ubicacion=reg[2])
                incident.update(fecha=reg[3])
                incident.update(id_tipo_incidente=reg[4])
                incident.update(tipo_incidente=reg[5])
                incident.update(id_municipio=reg[6])
                incident.update(municipio=reg[7])
                incident_list.append(incident)
            return incident_list


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
