use crate::routes::users::UserResponse;
use crate::{
	error::Error,
	generic::{surrealdb_client, Environment, GenericResponse},
	models::user::User,
};
use core::str;
use rocket::serde::json::Json;
use rocket::{http::Status, response::status};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

/// Set admin
#[utoipa::path(
    post,
    path = "/v1/bootstrap-admin",
    description = "Elevate a given User to an admin, providing only a secret key for authentication. Only available if there are fewer than 3 admins.",
    responses(
        (status = 200, description = "Admin set", body = [UserResponse]),
        (status = 401, description = "Unauthorized", body = GenericResponse),
    ),
    tag = "user"
)]
#[rocket::post("/v1/bootstrap-admin", data = "<request>")]
pub async fn bootstrap_admin_route(
	request: Json<BootstrapAdminRequest>,
) -> Result<Json<UserResponse>, status::Custom<Json<GenericResponse>>> {
	let request = request.into_inner();
	let response = bootstrap_admin(request.username, request.secret_key).await?;
	Ok(Json(response.into()))
}

pub async fn bootstrap_admin(username: String, secret_key: String) -> Result<User, Error> {
	let client = surrealdb_client().await?;
	let env_secret = Environment::new().surreal_password.val();
	let valid_key: bool = env_secret.as_bytes().ct_eq(secret_key.as_bytes()).into();

	if !valid_key {
		return Err(Error::generic_401());
	}

	if User::db_search(&client, "is_admin", true).await?.len() >= 3 {
		return Err(Error::new(
			Status::BadRequest,
			"Cannot bootstrap admin; there are already 3 or more admins",
			None,
		));
	}

	let user = User::db_search_one(&client, "username", username.to_owned())
		.await?
		.ok_or_else(|| {
			Error::new(
				Status::BadRequest,
				&format!("User `{}` does not exist", username),
				None,
			)
		})?;

	user.db_update_field(&client, "is_admin", &true).await?;
	Ok(user)
}

#[derive(Deserialize, ToSchema)]
pub struct BootstrapAdminRequest {
	/// The username of the existing user to elevate permissions.
	pub username: String,
	/// The SurrealDB password
	pub secret_key: String,
}
