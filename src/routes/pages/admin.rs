use crate::{
	error::{Error, ErrorResponse},
	generic::BearerToken,
	models::user::Role,
};
use rocket::{response::status, serde::json::Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct AdminPageResponse {
	all_roles: Vec<Role>,
}

#[rocket::get("/v1/page/admin")]
pub async fn admin(
	bearer_token: BearerToken,
) -> Result<Json<AdminPageResponse>, status::Custom<Json<ErrorResponse>>> {
	let session = bearer_token.validate().await?;
	let user = session.user().await?;

	if !user.has_role(&Role::Admin) {
		return Err(Error::forbidden().into());
	}

	Ok(Json(AdminPageResponse {
		all_roles: Role::all(),
	}))
}
