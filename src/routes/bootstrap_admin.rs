use crate::routes::users::UserResponse;
use crate::{
    error::Error,
    generic::{surrealdb_client, Environment, GenericResponse},
    models::user::User,
};
use core::str;
use rocket::response::status;
use rocket::serde::json::Json;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

/// Set admin
#[utoipa::path(
    post,
    path = "/v1/bootstrap-admin",
    description = "Elevate a given User to an admin, providing only a secret key for authentication. Only available if there are fewer than 3 admins.",
    request_body(content = BootstrapAdminRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Admin set", body = UserResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
    ),
    security(),
    tag = "user"
)]
#[rocket::post("/v1/bootstrap-admin", data = "<request>")]
pub async fn bootstrap_admin_route(
    request: Json<BootstrapAdminRequest>,
) -> Result<Json<UserResponse>, status::Custom<Json<GenericResponse>>> {
    let request = request.into_inner();
    let user = bootstrap_admin(request.username, request.secret_key).await?;
    Ok(Json(UserResponse::from_user(user).await?))
}

pub async fn bootstrap_admin(username: String, secret_key: String) -> Result<User, Error> {
    let client = surrealdb_client().await?;
    let env_secret = Environment::new().surreal_password.val();
    let valid_key: bool = env_secret.as_bytes().ct_eq(secret_key.as_bytes()).into();

    if !valid_key {
        return Err(Error::generic_401());
    }

    if User::db_search(&client, "is_admin", true).await?.len() >= 3 {
        return Err(Error::bad_request(
            "Cannot bootstrap admin; there are already 3 or more admins",
        ));
    }

    let user = User::db_search_one(&client, "username", username.to_owned())
        .await?
        .ok_or_else(|| Error::bad_request(&format!("User `{username}` does not exist")))?;

    user.db_update_field(&client, "is_admin", &true).await?;
    Ok(user)
}

/// Bootstrap Admin Request
#[derive(Deserialize, ToSchema)]
pub struct BootstrapAdminRequest {
    /// The username of the existing user to elevate permissions.
    pub username: String,
    /// The SurrealDB password
    pub secret_key: String,
}
