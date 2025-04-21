use crate::generic::BearerToken;
use crate::generic::GenericResponse;
use rocket::{get, http::Status, response::status, serde::json::Json};

#[utoipa::path(
    get,
    path = "/v1/auth/check_token",
    description = "Check whether the provided Bearer token is valid",
    responses(
        (status = 200, description = "Token valid", body = [GenericResponse]),
        (status = 401, description = "Unauthorized", body = GenericResponse),
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "auth"
)]
#[get("/v1/auth/check_token")]
/// Test Bearer token
pub async fn check_token(
	bearer_token: BearerToken,
) -> Result<Status, status::Custom<Json<GenericResponse>>> {
	bearer_token.validate().await?;
	Ok(Status::Ok)
}
