use crate::{error::ErrorResponse, generic::BearerToken};
use rocket::{get, http::Status, response::status, serde::json::Json};

#[get("/auth/check_token")]
/// Test Bearer token
pub async fn check_token(
	bearer_token: BearerToken,
) -> Result<Status, status::Custom<Json<ErrorResponse>>> {
	bearer_token.validate().await?;
	Ok(Status::Ok)
}
