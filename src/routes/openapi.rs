use crate::generic::DisplayName;
use crate::generic::GenericResponse;
use crate::generic::HasHandle;
use crate::generic::UniqueHandle;
use crate::routes::bootstrap_admin::BootstrapAdminRequest;
use crate::routes::bootstrap_admin::__path_bootstrap_admin_route;
use crate::routes::check_token::__path_check_token;
use crate::routes::establishment::EstablishmentCard;
use crate::routes::establishment::EstablishmentRequest;
use crate::routes::establishment::EstablishmentSearchRequest;
use crate::routes::establishment::__path_create_establishment;
use crate::routes::establishment::__path_get_establishment;
use crate::routes::establishment::__path_search_establishments_route;
use crate::routes::establishment::__path_update_establishment;
use crate::routes::token::__path_token_json;
use crate::routes::token::{TokenRequest, TokenResponse};
use crate::routes::users::RegistrationRequest;
use crate::routes::users::UserResponse;
use crate::routes::users::__path_change_password;
use crate::routes::users::__path_delete_user;
use crate::routes::users::__path_get_user;
use crate::routes::users::__path_get_users;
use crate::routes::users::__path_register;
use crate::routes::users::__path_update_user;
use crate::routes::users::{ChangePasswordRequest, UserRequest};
use rocket::response::content::RawHtml;
use rocket::{get, serde::json::Json};
use serde::Deserialize;
use serde::Serialize;
use surreal_socket::dbrecord::DBRecord;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::Modify;
use utoipa::OpenApi;
use utoipa::ToSchema;
use utoipa_rapidoc::RapiDoc;

#[derive(OpenApi)]
#[openapi(
	info(
        title = "MyKavaBar API",
        description = "https://github.com/MyKavaBarLLC/mykavabar-backend"
    ),
	paths(token_json, register, change_password, update_user, delete_user, get_user, get_users, bootstrap_admin_route, check_token, get_establishment, create_establishment, search_establishments_route, update_establishment),
	components(schemas(DisplayName, UniqueHandle<HandleDummy>, TokenRequest, TokenResponse, GenericResponse, RegistrationRequest, ChangePasswordRequest, UserRequest, UserResponse, BootstrapAdminRequest, EstablishmentSearchRequest, EstablishmentCard, EstablishmentRequest, DummySuccess)),
	tags((name = "auth", description = "OAuth 2.0 Authentication"),
		(name = "user", description = "User management endpoints. Use `me` in place of user ID to refer to the authenticated user"),
		(name = "establishment", description = "Establishment management endpoints")
	),
	security(
		("bearerAuth" = [])
	),
	modifiers(&BearerTokenSecurity)
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

pub struct BearerTokenSecurity;

impl Modify for BearerTokenSecurity {
	fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
		let components = openapi.components.get_or_insert_with(Default::default);

		components.add_security_scheme(
			"bearerAuth",
			SecurityScheme::Http(
				HttpBuilder::new()
					.scheme(HttpAuthScheme::Bearer)
					.bearer_format("JWT")
					.build(),
			),
		);
	}
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct HandleDummy;

impl DBRecord for HandleDummy {
	const TABLE_NAME: &'static str = unimplemented!();

	fn uuid(&self) -> surreal_socket::dbrecord::SsUuid<Self> {
		unimplemented!()
	}
}

impl HasHandle for HandleDummy {
	fn handle_field() -> &'static str {
		unimplemented!()
	}
}

// Use as the doc component for successful responses because
// GenericResponse uses false as the example `success` value
#[derive(Serialize, Deserialize, ToSchema)]
pub struct DummySuccess {
	#[schema(example = true)]
	success: bool,
	#[schema(example = json!(null))]
	error: Option<String>,
}
