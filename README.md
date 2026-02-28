# API RESTful - Sistema de Gestion de Inventario (Tienda de Perifericos)

Una API RESTful robusta, segura y completamente documentada, diseñada para la gestion de inventario de una tienda de perifericos de computadora. Este proyecto fue desarrollado en Rust para garantizar un alto rendimiento, seguridad en el manejo de memoria y concurrencia eficiente.

---

## Caracteristicas Principales

* Autenticacion y Autorizacion: Sistema de registro y login de usuarios con contraseñas encriptadas mediante hashing (Bcrypt). Las rutas privadas estan protegidas mediante la generacion y validacion de JSON Web Tokens (JWT) con fecha de expiracion.
* Operaciones CRUD: Endpoints estructurados para Crear, Leer, Actualizar y Eliminar (CRUD) productos del inventario.
* Base de Datos Embebida: Implementacion de SQLite a traves de `sqlx` para un almacenamiento persistente y transaccional sin requerir configuraciones de servidores externos.
* Documentacion Interactiva: Integracion nativa con Swagger UI (OpenAPI) que permite explorar y probar los endpoints directamente desde el navegador web.
* Contenerizacion: Entorno de ejecucion aislado y replicable mediante Docker, facilitando el despliegue continuo en entornos de produccion.

---

## Tecnologias y Dependencias

* Lenguaje: Rust
* Framework Web: Axum (Manejo de rutas y peticiones HTTP)
* Base de Datos: SQLite (Gestionada con `sqlx`)
* Seguridad: `jsonwebtoken` (Generacion y validacion de JWT), `bcrypt` (Hashing de credenciales)
* Serializacion: `serde` y `serde_json`
* Documentacion: `utoipa` y `utoipa-swagger-ui`
* Despliegue: Docker y Render

---

## Prerrequisitos

Para ejecutar este proyecto en un entorno local, se requiere tener instalado:
1. Rust y Cargo (Version mas reciente recomendada).
2. Docker y Docker Desktop (Para la construccion y ejecucion de contenedores).

---

## Guia de Uso y Flujo de Pruebas

Para probar el funcionamiento de la API a traves de Swagger UI, siga este flujo operativo:

1. Registro de Usuario: Dirijase a `POST /api/v1/registrar` e ingrese un nombre de usuario y contraseña en el cuerpo de la peticion (JSON).
2. Autenticacion: Dirijase a `POST /api/v1/login` utilizando las credenciales creadas. Copie el token JWT generado en la respuesta.
3. Autorizacion: En la parte superior de Swagger UI, haga clic en el boton "Authorize". Ingrese el token copiado asegurandose de incluir la palabra Bearer al inicio (ejemplo: `Bearer eyJhbGci...`).
4. Gestion de Inventario: Una vez autorizado, podra ejecutar peticiones a los endpoints protegidos:
   * `GET /api/v1/productos` (Listar perifericos)
   * `POST /api/v1/productos` (Registrar un nuevo periferico)
   * `PUT /api/v1/productos/:id` (Actualizar datos de un periferico existente)
   * `DELETE /api/v1/productos/:id` (Eliminar un periferico de la base de datos)

---

## Instalacion y Ejecucion Local

1. Clone el repositorio y navegue hasta el directorio raiz del proyecto.
2. Compile y ejecute el servidor web utilizando Cargo:
   ```bash
   cargo run