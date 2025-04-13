use crate::error::ErrorResponse;
use crate::routes::token::__path_token_json;
use crate::routes::token::{TokenRequest, TokenResponse};
use crate::routes::users::RegistrationRequest;
use crate::routes::users::__path_change_password;
use crate::routes::users::__path_delete_user;
use crate::routes::users::__path_register;
use crate::routes::users::__path_update_user;
use crate::routes::users::{ChangePasswordRequest, UpdateUserRequest};
use rocket::response::content::RawHtml;
use rocket::{get, serde::json::Json};
use utoipa::OpenApi;
use utoipa_rapidoc::RapiDoc;

#[derive(OpenApi)]
#[openapi(
    paths(token_json, register, change_password, update_user, delete_user),
    components(schemas(TokenRequest, TokenResponse, ErrorResponse, RegistrationRequest, ChangePasswordRequest, UpdateUserRequest)),
    tags((name = "auth", description = "OAuth 2.0 Authentication"),
    (name = "user", description = "User Management endpoints. Use `me` in place of user ID to refer to the authenticated user.")),
	security(
		("bearerAuth" = [])
	)
)]
pub struct ApiDoc;

#[get("/v1/openapi.json")]
pub fn openapi_route() -> Json<utoipa::openapi::OpenApi> {
	Json(ApiDoc::openapi())
}

#[get("/v1/rapidoc")]
pub fn rapidoc() -> RawHtml<String> {
	RawHtml(RapiDoc::new("/v1/openapi.json").to_html())
}
