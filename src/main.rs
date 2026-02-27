use axum::{extract::State, routing::post, Json, Router};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, Pool, Sqlite, Row};
use std::str::FromStr;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// --- ESTRUCTURAS ---
#[derive(Deserialize, ToSchema)]
struct LoginRequest {
    usuario: String,
    password: String,
}

#[derive(Serialize, ToSchema)]
struct LoginResponse {
    mensaje: String,
    exito: bool,
}

// --- RUTA DE LOGIN CON SWAGGER ---
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login exitoso", body = LoginResponse),
        (status = 401, description = "Credenciales incorrectas")
    )
)]
async fn login(
    State(pool): State<Pool<Sqlite>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, axum::http::StatusCode> {
    
    // Buscamos al usuario en la base de datos SQLite
    let record = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&payload.usuario)
        .fetch_optional(&pool)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(row) = record {
        let hash_guardado: String = row.try_get("password_hash").unwrap();
        
        // Verificamos si la contraseña coincide con el hash de la DB
        if verify(&payload.password, &hash_guardado).unwrap_or(false) {
            return Ok(Json(LoginResponse {
                mensaje: "Bienvenido, token generado.".to_string(),
                exito: true,
            }));
        }
    }

    // Si no existe el usuario o la clave está mal
    Err(axum::http::StatusCode::UNAUTHORIZED)
}

// --- CONFIGURACIÓN DE SWAGGER ---
#[derive(OpenApi)]
#[openapi(paths(login), components(schemas(LoginRequest, LoginResponse)))]
struct ApiDoc;

// --- INICIO DEL SERVIDOR ---
#[tokio::main]
async fn main() {
    // 1. Configurar SQLite (Crea el archivo "tarea.db" si no existe)
    let db_options = SqliteConnectOptions::from_str("sqlite://tarea.db")
        .unwrap()
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .connect_with(db_options)
        .await
        .unwrap();

    // 2. Crear la tabla de usuarios
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT
        )"
    )
    .execute(&pool)
    .await
    .unwrap();

    // 3. Insertar un usuario "admin" con contraseña "12345" hasheada (para pruebas del profe)
    let admin_pass = hash("12345", DEFAULT_COST).unwrap();
    sqlx::query("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('admin', ?)")
        .bind(admin_pass)
        .execute(&pool)
        .await
        .unwrap();

    // 4. Levantar las rutas (inyectando la base de datos)
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/login", post(login))
        .with_state(pool); // Pasamos la conexión de DB a las rutas

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 API corriendo en http://localhost:8080/swagger-ui");
    axum::serve(listener, app).await.unwrap();
}