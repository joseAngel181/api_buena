use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, Pool, Row, Sqlite};
use std::str::FromStr;
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

#[derive(Serialize, ToSchema)]
struct UsuarioResponse { id: u32, username: String }

#[derive(Deserialize, ToSchema)]
struct ProductoRequest { nombre: String, precio: f64 }

#[derive(Serialize, ToSchema)]
struct ProductoResponse { id: u32, nombre: String, precio: f64 }

#[derive(Serialize, ToSchema)]
struct MensajeResponse { mensaje: String }

// ==========================================
// SEGURIDAD (TOKEN)
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

fn verificar_token(headers: &HeaderMap) -> bool {
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            return auth_str == "Bearer token_secreto_api_123";
        }
    }
    false
}

// ==========================================
// RUTAS (ENDPOINTS)
// ==========================================

// --- HEALTH CHECK ---
#[utoipa::path(get, path = "/api/v1/health", responses((status = 200, description = "Servidor OK")))]
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "mensaje": "Servidor funcionando correctamente"}))
}

// --- LOGIN ---
#[utoipa::path(post, path = "/api/v1/login", request_body = AuthRequest, responses((status = 200, description = "Login exitoso", body = AuthResponse), (status = 401, description = "Error")))]
async fn login(State(pool): State<Pool<Sqlite>>, Json(payload): Json<AuthRequest>) -> Result<Json<AuthResponse>, StatusCode> {
    let record = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&payload.usuario).fetch_optional(&pool).await.unwrap();

    if let Some(row) = record {
        let hash_guardado: String = row.try_get("password_hash").unwrap();
        if verify(&payload.password, &hash_guardado).unwrap_or(false) {
            return Ok(Json(AuthResponse { mensaje: "Acceso concedido".to_string(), token: Some("token_secreto_api_123".to_string()) }));
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// --- REGISTRAR USUARIO ---
#[utoipa::path(post, path = "/api/v1/usuarios", request_body = AuthRequest, responses((status = 201, description = "Usuario creado", body = MensajeResponse)))]
async fn registrar_usuario(State(pool): State<Pool<Sqlite>>, Json(payload): Json<AuthRequest>) -> Result<Json<MensajeResponse>, StatusCode> {
    let hash_pass = hash(&payload.password, DEFAULT_COST).unwrap();
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&payload.usuario).bind(hash_pass).execute(&pool).await;

    match result {
        Ok(_) => Ok(Json(MensajeResponse { mensaje: "Usuario registrado exitosamente".to_string() })),
        Err(_) => Err(StatusCode::BAD_REQUEST), // Falla si el usuario ya existe
    }
}

// --- OBTENER TODOS LOS USUARIOS (Protegido) ---
#[utoipa::path(get, path = "/api/v1/usuarios", responses((status = 200, description = "Lista de usuarios", body = [UsuarioResponse])), security(("TokenBearer" = [])))]
async fn obtener_usuarios(State(pool): State<Pool<Sqlite>>, headers: HeaderMap) -> Result<Json<Vec<UsuarioResponse>>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    
    let rows = sqlx::query("SELECT id, username FROM users").fetch_all(&pool).await.unwrap();
    let usuarios = rows.into_iter().map(|row| UsuarioResponse {
        id: row.try_get("id").unwrap(), username: row.try_get("username").unwrap(),
    }).collect();
    
    Ok(Json(usuarios))
}

// --- OBTENER USUARIO POR ID (Protegido) ---
#[utoipa::path(get, path = "/api/v1/usuarios/{id}", params(("id" = u32, Path, description = "ID del usuario")), responses((status = 200, description = "Usuario encontrado", body = UsuarioResponse)), security(("TokenBearer" = [])))]
async fn obtener_usuario_id(State(pool): State<Pool<Sqlite>>, Path(id): Path<u32>, headers: HeaderMap) -> Result<Json<UsuarioResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }

    let row = sqlx::query("SELECT id, username FROM users WHERE id = ?").bind(id).fetch_optional(&pool).await.unwrap();
    match row {
        Some(r) => Ok(Json(UsuarioResponse { id: r.try_get("id").unwrap(), username: r.try_get("username").unwrap() })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// --- INSERTAR PRODUCTO (Protegido) ---
#[utoipa::path(post, path = "/api/v1/productos", request_body = ProductoRequest, responses((status = 201, description = "Producto creado", body = MensajeResponse)), security(("TokenBearer" = [])))]
async fn insertar_producto(State(pool): State<Pool<Sqlite>>, headers: HeaderMap, Json(payload): Json<ProductoRequest>) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }

    sqlx::query("INSERT INTO productos (nombre, precio) VALUES (?, ?)").bind(&payload.nombre).bind(payload.precio).execute(&pool).await.unwrap();
    Ok(Json(MensajeResponse { mensaje: "Producto (Periférico) registrado correctamente".to_string() }))
}

// ==========================================
// CONFIGURACIÓN DE SWAGGER Y SERVIDOR
// ==========================================
#[derive(OpenApi)]
#[openapi(
    paths(health, login, registrar_usuario, obtener_usuarios, obtener_usuario_id, insertar_producto),
    components(schemas(AuthRequest, AuthResponse, UsuarioResponse, ProductoRequest, ProductoResponse, MensajeResponse)),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

#[tokio::main]
async fn main() {
    let db_options = SqliteConnectOptions::from_str("sqlite://tarea.db").unwrap().create_if_missing(true);
    let pool = SqlitePoolOptions::new().connect_with(db_options).await.unwrap();

    // Crear tablas
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)").execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS productos (id INTEGER PRIMARY KEY, nombre TEXT, precio REAL)").execute(&pool).await.unwrap();
    
    // Insertar admin por defecto
    let admin_pass = hash("12345", DEFAULT_COST).unwrap();
    sqlx::query("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('admin', ?)").bind(admin_pass).execute(&pool).await.unwrap();

    let app = Router::new()
        // La ruta raíz "/" redirige automáticamente a los documentos de Swagger
        .route("/", get(|| async { Redirect::temporary("/swagger-ui") }))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/health", get(health))
        .route("/api/v1/login", post(login))
        .route("/api/v1/usuarios", post(registrar_usuario).get(obtener_usuarios))
        .route("/api/v1/usuarios/{id}", get(obtener_usuario_id))
        .route("/api/v1/productos", post(insertar_producto))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Servidor corriendo. Entra a http://localhost:8080/");
    axum::serve(listener, app).await.unwrap();
}