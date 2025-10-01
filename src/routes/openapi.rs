use crate::generic::DisplayName;
use crate::generic::GenericResponse;
use crate::generic::HasHandle;
use crate::generic::UniqueHandle;
use crate::models::establishment::Coordinate;
use crate::models::establishment::EstablishmentRating;
use crate::models::establishment::Schedule;
use crate::models::event::EventResponse;
use crate::routes::bootstrap_admin::BootstrapAdminRequest;
use crate::routes::bootstrap_admin::__path_bootstrap_admin_route;
use crate::routes::check_token::__path_check_token;
use crate::routes::establishment::*;
use crate::routes::events::*;
use crate::routes::token::__path_token_json;
use crate::routes::token::{TokenRequest, TokenResponse};
use crate::routes::users::*;
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
    paths(token_json, register, change_password, update_user, delete_user, get_user, get_users, bootstrap_admin_route, check_token, get_establishment, create_establishment, search_establishments_route, update_establishment, delete_establishment, update_establishment_staff, delete_establishment_staff, add_establishment_staff, add_establishment_review, update_establishment_review, delete_establishment_review, check_in, check_out, create_event, get_events, update_event, delete_event, get_upcoming_events),
    components(schemas(DisplayName, UniqueHandle<HandleDummy>, TokenRequest, TokenResponse, GenericResponse, RegistrationRequest, ChangePasswordRequest, UserRequest, UserResponse, BootstrapAdminRequest, EstablishmentSearchRequest, EstablishmentCard, EstablishmentRequest, DummySuccess, ReviewDto, Coordinate, Schedule, EstablishmentRating, EventRequest, EventResponse)),
    tags((name = "auth", description = "OAuth 2.0 Authentication"),
        (name = "user", description = "User endpoints. Use `me` in place of user ID to refer to the authenticated user"),
        (name = "establishment", description = "Establishment endpoints"),
        (name = "event", description = "Event endpoints"),
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
