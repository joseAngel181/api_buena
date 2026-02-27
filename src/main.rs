use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Pool, Row, Sqlite,
};
use std::str::FromStr;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;

// --- ESTRUCTURAS ---
#[derive(Deserialize, ToSchema)]
struct LoginRequest { usuario: String, password: String }

#[derive(Serialize, ToSchema)]
struct LoginResponse { mensaje: String, token: Option<String> }

#[derive(Serialize, ToSchema)]
struct MensajeResponse { mensaje: String }

// --- CONFIGURACIÓN DEL CANDADO EN SWAGGER (BEARER TOKEN) ---
struct SecurityAddon;
impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "TokenBearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

// --- FUNCIÓN PARA VALIDAR EL TOKEN ---
fn verificar_token(headers: &HeaderMap) -> bool {
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            // Verificamos que el usuario mande el token correcto
            return auth_str == "Bearer token_secreto_universidad_123";
        }
    }
    false
}

// ==========================================
// RUTAS HTTP (CRUD COMPLETO)
// ==========================================

// 1. POST (Crear sesión / Login)
#[utoipa::path(
    post, path = "/login", request_body = LoginRequest,
    responses((status = 200, description = "Login exitoso", body = LoginResponse), (status = 401, description = "Error"))
)]
async fn login(State(pool): State<Pool<Sqlite>>, Json(payload): Json<LoginRequest>) -> Result<Json<LoginResponse>, StatusCode> {
    let record = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&payload.usuario).fetch_optional(&pool).await.unwrap();

    if let Some(row) = record {
        let hash_guardado: String = row.try_get("password_hash").unwrap();
        if verify(&payload.password, &hash_guardado).unwrap_or(false) {
            return Ok(Json(LoginResponse {
                mensaje: "Acceso concedido".to_string(),
                token: Some("token_secreto_universidad_123".to_string()), // Retornamos el token simulado
            }));
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// 2. GET (Leer datos protegidos)
#[utoipa::path(
    get, path = "/datos",
    responses((status = 200, description = "Datos obtenidos", body = MensajeResponse), (status = 401, description = "Falta Token")),
    security(("TokenBearer" = [])) // Esto pone el candadito en Swagger
)]
async fn obtener_datos(headers: HeaderMap) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    Ok(Json(MensajeResponse { mensaje: "Aquí tienes los datos secretos".to_string() }))
}

// 3. PUT (Actualizar datos)
#[utoipa::path(
    put, path = "/datos/{id}",
    params(("id" = u32, Path, description = "ID del dato a actualizar")),
    responses((status = 200, description = "Dato actualizado", body = MensajeResponse), (status = 401, description = "Falta Token")),
    security(("TokenBearer" = []))
)]
async fn actualizar_dato(Path(id): Path<u32>, headers: HeaderMap) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    Ok(Json(MensajeResponse { mensaje: format!("El dato {} fue actualizado correctamente", id) }))
}

// 4. DELETE (Eliminar datos)
#[utoipa::path(
    delete, path = "/datos/{id}",
    params(("id" = u32, Path, description = "ID del dato a eliminar")),
    responses((status = 200, description = "Dato eliminado", body = MensajeResponse), (status = 401, description = "Falta Token")),
    security(("TokenBearer" = []))
)]
async fn eliminar_dato(Path(id): Path<u32>, headers: HeaderMap) -> Result<Json<MensajeResponse>, StatusCode> {
    if !verificar_token(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    Ok(Json(MensajeResponse { mensaje: format!("El dato {} fue eliminado", id) }))
}

// --- CONFIGURACIÓN DE SWAGGER ---
#[derive(OpenApi)]
#[openapi(
    paths(login, obtener_datos, actualizar_dato, eliminar_dato),
    components(schemas(LoginRequest, LoginResponse, MensajeResponse)),
    modifiers(&SecurityAddon) // Activamos el botón de Authorize
)]
struct ApiDoc;

// --- INICIO DEL SERVIDOR ---
#[tokio::main]
async fn main() {
    let db_options = SqliteConnectOptions::from_str("sqlite://tarea.db").unwrap().create_if_missing(true);
    let pool = SqlitePoolOptions::new().connect_with(db_options).await.unwrap();

    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)").execute(&pool).await.unwrap();
    let admin_pass = hash("12345", DEFAULT_COST).unwrap();
    sqlx::query("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('admin', ?)").bind(admin_pass).execute(&pool).await.unwrap();

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/login", post(login))
        .route("/datos", get(obtener_datos))
        .route("/datos/{id}", put(actualizar_dato))
        .route("/datos/{id}", delete(eliminar_dato))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 API corriendo en http://localhost:8080/swagger-ui");
    axum::serve(listener, app).await.unwrap();
}