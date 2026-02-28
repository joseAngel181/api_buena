use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{delete, get, post, put},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, Pool, Row, Sqlite};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;

// ==========================================
// ESTRUCTURAS DE DATOS (SCHEMAS)
// ==========================================
#[derive(Deserialize, ToSchema)]
struct AuthRequest { usuario: String, password: String }

#[derive(Serialize, ToSchema)]
struct AuthResponse { mensaje: String, token: Option<String> }

#[derive(Deserialize, ToSchema)]
struct ProductoRequest { nombre: String, precio: f64 }

#[derive(Serialize, ToSchema)]
struct ProductoResponse { id: u32, nombre: String, precio: f64 }

#[derive(Serialize, ToSchema)]
struct MensajeResponse { mensaje: String }

// ==========================================
// SEGURIDAD: JWT (JSON WEB TOKENS)
// ==========================================
struct SecurityAddon;
impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "TokenBearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).bearer_format("JWT").build()),
        );
    }
}

// Estructura interna del Token
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // El usuario
    exp: usize,  // Fecha de expiración
}

const SECRET_KEY: &[u8] = b"mi_super_secreto_universitario_123";

// Función para validar que el token criptográfico sea real y no haya caducado
fn verificar_token(headers: &HeaderMap) -> bool {
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = auth_str.trim_start_matches("Bearer ");
                let validation = Validation::new(Algorithm::HS256);
                return decode::<Claims>(token, &DecodingKey::from_secret(SECRET_KEY), &validation).is_ok();
            }
        }
    }
    false
}

// ==========================================
// RUTAS (ENDPOINTS)
// ==========================================

// --- REGISTRAR USUARIO (POST) ---
#[utoipa::path(post, path = "/api/v1/registrar", request_body = AuthRequest, responses((status = 201, description = "Usuario creado", body = MensajeResponse)))]
async fn registrar_usuario(State(pool): State<Pool<Sqlite>>, Json(payload): Json<AuthRequest>) -> Result<Json<MensajeResponse>, StatusCode> {
    let hash_pass = hash(&payload.password, DEFAULT_COST).unwrap();
    match sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(&payload.usuario).bind(hash_pass).execute(&pool).await {
        Ok(_) => Ok(Json(MensajeResponse { mensaje: "Usuario registrado exitosamente".to_string() })),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

// --- LOGIN Y GENERACIÓN DE JWT DINÁMICO (POST) ---
#[utoipa::path(post, path = "/api/v1/login", request_body = AuthRequest, responses((status = 200, description = "Login exitoso", body = AuthResponse), (status = 401, description = "Credenciales inválidas")))]
async fn login(State(pool): State<Pool<Sqlite>>, Json(payload): Json<AuthRequest>) -> Result<Json<AuthResponse>, StatusCode> {
    let record = sqlx::query("SELECT password_hash FROM users WHERE username = ?").bind(&payload.usuario).fetch_optional(&pool).await.unwrap();
    if let Some(row) = record {
        let hash_guardado: String = row.try_get("password_hash").unwrap();
        if verify(&payload.password, &hash_guardado).unwrap_or(false) {
            
            // Generar Token Real que caduca en 2 horas
            let expiracion = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize + 7200;
            let claims = Claims { sub: payload.usuario.clone(), exp: expiracion };
            let token_real = encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY)).unwrap();

            return Ok(Json(AuthResponse { mensaje: "Acceso concedido".to_string(), token: Some(token_real) }));
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// --- CREAR PRODUCTO (POST) ---
#[utoipa::path(post, path = "/api/v1/productos", request_body = ProductoRequest, responses((status = 201, description = "Producto creado", body = MensajeResponse), (status = 401, description = "Falta Token")), security(("TokenBearer" = [])))]
async fn crear_producto(State(pool): State<Pool<Sqlite>>, headers: HeaderMap, Json(payload): Json<ProductoRequest>) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    sqlx::query("INSERT INTO productos (nombre, precio) VALUES (?, ?)").bind(&payload.nombre).bind(payload.precio).execute(&pool).await.unwrap();
    Ok(Json(MensajeResponse { mensaje: "Producto registrado correctamente en la Base de Datos".to_string() }))
}

// --- OBTENER PRODUCTOS (GET) ---
#[utoipa::path(get, path = "/api/v1/productos", responses((status = 200, description = "Lista de productos", body = [ProductoResponse]), (status = 401, description = "Falta Token")), security(("TokenBearer" = [])))]
async fn obtener_productos(State(pool): State<Pool<Sqlite>>, headers: HeaderMap) -> Result<Json<Vec<ProductoResponse>>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let rows = sqlx::query("SELECT id, nombre, precio FROM productos").fetch_all(&pool).await.unwrap();
    let productos = rows.into_iter().map(|row| ProductoResponse { id: row.try_get("id").unwrap(), nombre: row.try_get("nombre").unwrap(), precio: row.try_get("precio").unwrap() }).collect();
    Ok(Json(productos))
}

// --- ACTUALIZAR PRODUCTO (PUT) ---
#[utoipa::path(put, path = "/api/v1/productos/{id}", params(("id" = u32, Path, description = "ID del producto")), request_body = ProductoRequest, responses((status = 200, description = "Producto actualizado", body = MensajeResponse), (status = 401, description = "Falta Token")), security(("TokenBearer" = [])))]
async fn actualizar_producto(State(pool): State<Pool<Sqlite>>, Path(id): Path<u32>, headers: HeaderMap, Json(payload): Json<ProductoRequest>) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    sqlx::query("UPDATE productos SET nombre = ?, precio = ? WHERE id = ?").bind(&payload.nombre).bind(payload.precio).bind(id).execute(&pool).await.unwrap();
    Ok(Json(MensajeResponse { mensaje: format!("Producto {} actualizado", id) }))
}

// --- ELIMINAR PRODUCTO (DELETE) ---
#[utoipa::path(delete, path = "/api/v1/productos/{id}", params(("id" = u32, Path, description = "ID del producto")), responses((status = 200, description = "Producto eliminado", body = MensajeResponse), (status = 401, description = "Falta Token")), security(("TokenBearer" = [])))]
async fn eliminar_producto(State(pool): State<Pool<Sqlite>>, Path(id): Path<u32>, headers: HeaderMap) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let result = sqlx::query("DELETE FROM productos WHERE id = ?").bind(id).execute(&pool).await.unwrap();
    
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND); // Si pones un ID que no existe
    }
    Ok(Json(MensajeResponse { mensaje: format!("Producto {} eliminado permanentemente", id) }))
}

// ==========================================
// CONFIGURACIÓN DE SWAGGER Y SERVIDOR
// ==========================================
#[derive(OpenApi)]
#[openapi(
    paths(registrar_usuario, login, crear_producto, obtener_productos, actualizar_producto, eliminar_producto),
    components(schemas(AuthRequest, AuthResponse, ProductoRequest, ProductoResponse, MensajeResponse)),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

#[tokio::main]
async fn main() {
    let db_options = SqliteConnectOptions::from_str("sqlite://tarea.db").unwrap().create_if_missing(true);
    let pool = SqlitePoolOptions::new().connect_with(db_options).await.unwrap();

    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)").execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS productos (id INTEGER PRIMARY KEY, nombre TEXT, precio REAL)").execute(&pool).await.unwrap();
    
    let app = Router::new()
        .route("/", get(|| async { Redirect::temporary("/swagger-ui") }))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/registrar", post(registrar_usuario))
        .route("/api/v1/login", post(login))
        .route("/api/v1/productos", get(obtener_productos).post(crear_producto))
        // 👇 AQUÍ ESTABA EL BUG: Cambié {id} por :id para que el router de Axum lo detecte correctamente
        .route("/api/v1/productos/:id", put(actualizar_producto).delete(eliminar_producto))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 API corriendo en http://localhost:8080/swagger-ui");
    axum::serve(listener, app).await.unwrap();
}