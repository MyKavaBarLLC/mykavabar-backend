use crate::{
	error::{Error, ErrorResponse},
	generic::{surrealdb_client, BearerToken, GenericOkResponse},
	models::{
		session::Session,
		user::{Role, User},
	},
	routes::token::{token, TokenRequest, TokenResponse},
};
use core::str;
use rocket::{
	http::Status,
	response::status,
	serde::{json::Json, Deserialize},
};
use serde_json::json;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct RegistrationRequest {
	pub username: String,
	pub display_name: String,
	pub password: String,
}

#[utoipa::path(
    post,
    path = "/v1/register_user",
	description = "Register user",
    request_body(content = RegistrationRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "User registered and token granted", body = TokenResponse),
        (status = 400, description = "Bad request", body = ErrorResponse)
    ),
    tag = "auth"
)]
#[rocket::post("/v1/register_user", format = "json", data = "<registration>")]
pub async fn register(
	registration: Json<RegistrationRequest>,
) -> Result<Json<TokenResponse>, status::Custom<Json<ErrorResponse>>> {
	let registration = registration.into_inner();
	let user = User::register(&registration).await?;

	// Log them in
	let token_request = TokenRequest::new_password_grant(&user.username, &registration.password);

	token(token_request).await
}

/// Retrieves a user by their ID, subject to security checks based on the session.
///
/// This function accepts a user ID and a session. If the ID is "me", it returns the session's user.
/// Otherwise, it returns the user corresponding to the provided ID only if the session's user is
/// the same as the user with the ID or if the session's user is an admin.
async fn get_user(id: &str, session: Session) -> Result<User, Error> {
	if id == "me" {
		session.user().await
	} else {
		match User::db_by_id(&surrealdb_client().await?, id).await? {
			Some(target_user) => {
				let session_user = session.user().await?;

				if target_user.uuid != session_user.uuid() && !session_user.has_role(&Role::Admin) {
					return Err(Error::insufficient_permissions());
				}

				Ok(target_user)
			}
			None => Err(Error::new(Status::NotFound, "User not found", None)),
		}
	}
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
	pub old_password: String,
	pub new_password: String,
}

#[utoipa::path(
    post,
    path = "/v1/users/{id}/change_password",
	description = "Change password",
    request_body(content = ChangePasswordRequest, content_type = "application/json"),
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Password changed", body = GenericOkResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::post("/v1/users/<id>/change_password", format = "json", data = "<request>")]
pub async fn change_password(
	id: String,
	request: Json<ChangePasswordRequest>,
	bearer_token: BearerToken,
) -> Result<Json<GenericOkResponse>, status::Custom<Json<ErrorResponse>>> {
	let session = bearer_token.validate().await?;
	let mut user = get_user(&id, session).await?;

	if user.verify_password(&request.old_password).is_err() {
		return Err(Error::new(Status::Unauthorized, "Invalid password", None).into());
	}

	user.set_password(&request.new_password).await?;
	Ok(Json(GenericOkResponse::new()))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateUserRequest {
	pub username: Option<String>,
	pub display_name: Option<String>,

	/// Only admins can change the password of a user with this endpoint.
	/// Users can change their own password by using the change_password endpoint.
	/// This is because users must provide their current password to change it.
	pub password: Option<String>,
}

#[utoipa::path(
    patch,
    path = "/v1/users/{id}",
	description = "Update user",
    request_body(content = UpdateUserRequest, content_type = "application/json"),
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User updated", body = GenericOkResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::patch("/v1/users/<id>", format = "json", data = "<request>")]
pub async fn update_user(
	id: &str,
	request: Json<UpdateUserRequest>,
	bearer_token: BearerToken,
) -> Result<Json<GenericOkResponse>, status::Custom<Json<ErrorResponse>>> {
	let session = bearer_token.validate().await?;
	let is_admin_request = session.user().await?.has_role(&Role::Admin);
	let mut user = get_user(id, session).await?;
	let mut updates = vec![];

	if let Some(username) = &request.username {
		let username = User::validate_username_requirements(username)?;
		updates.push(("username", json!(username)));
	}

	if let Some(display_name) = &request.display_name {
		let display_name = User::validate_displayname_requirements(display_name)?;
		updates.push(("display_name", json!(display_name)));
	}

	if let Some(password) = &request.password {
		if is_admin_request {
			user.set_password(password).await?;
		} else {
			// Users change their own password with the change_password endpoint
			return Err(Error::insufficient_permissions().into());
		}
	}

	user.db_update_fields(
		&surrealdb_client().await.map_err(Into::<Error>::into)?,
		updates,
	)
	.await
	.map_err(Into::<Error>::into)?;

	Ok(Json(GenericOkResponse::new()))
}

#[utoipa::path(
    delete,
    path = "/v1/users/{id}",
    description = "Delete user",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User deleted", body = GenericOkResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::delete("/v1/users/<id>")]
pub async fn delete_user(
	id: &str,
	bearer_token: BearerToken,
) -> Result<Json<GenericOkResponse>, status::Custom<Json<ErrorResponse>>> {
	let session = bearer_token.validate().await?;
	let user = get_user(id, session).await?;

	user.db_delete(&surrealdb_client().await.map_err(Into::<Error>::into)?)
		.await
		.map_err(Into::<Error>::into)?;

	Ok(Json(GenericOkResponse::new()))
}

// TODO: Create response struct for this & add utoipa docs
/// Get every user in the database. Admins only.
#[rocket::get("/v1/users")]
pub async fn get_users(
	bearer_token: BearerToken,
) -> Result<Json<Vec<User>>, status::Custom<Json<ErrorResponse>>> {
	let session = bearer_token.validate().await?;
	let user = session.user().await?;

	if !user.has_role(&Role::Admin) {
		return Err(Error::insufficient_permissions().into());
	}

	let mut users = User::db_all(&surrealdb_client().await.map_err(Into::<Error>::into)?)
		.await
		.map_err(Into::<Error>::into)?;

	// Don't include password hashes in the response
	for user in &mut users {
		user.password_hash = Default::default();
	}

	Ok(Json(users))
}
