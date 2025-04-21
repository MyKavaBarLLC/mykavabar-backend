use crate::{error::Error, generic::GenericResponse, routes};
use rocket::{
	catch, catchers,
	fairing::{Fairing, Info, Kind},
	fs::{relative, NamedFile},
	get,
	response::Redirect,
	serde::json::Json,
	shield::{Hsts, Shield},
	time::Duration,
	uri, Orbit, Request, Rocket,
};
use serde::Serialize;
use std::{
	path::{Path, PathBuf},
	sync::{Arc, Mutex},
};

#[rocket::get("/<path..>")]
pub async fn static_pages(path: PathBuf) -> Option<NamedFile> {
	let mut path = Path::new(relative!("static")).join(path);
	if path.is_dir() {
		path.push("index.html");
	}
	NamedFile::open(path).await.ok()
}

#[derive(Serialize)]
pub struct VersionInfo {
	version: String,
}

#[rocket::get("/version")]
pub fn version() -> Json<VersionInfo> {
	Json(VersionInfo {
		version: env!("CARGO_PKG_VERSION").to_string(),
	})
}

pub async fn start_web(bound_port: BoundPort) {
	if let Err(e) = rocket::build()
		.mount(
			"/",
			rocket::routes![
				root_redirect,
				static_pages,
				version,
				routes::openapi::openapi_route,
				routes::openapi::rapidoc,
				// Auth
				routes::token::token_json,
				routes::token::token_form,
				routes::check_token::check_token,
				// Users
				routes::users::register,
				routes::users::change_password,
				routes::users::get_users,
				routes::users::update_user,
				routes::users::delete_user,
				routes::bootstrap_admin::bootstrap_admin_route,
				// Establishments
				routes::establishment::create_establishment,
				routes::establishment::get_establishment,
				routes::establishment::search_establishments_route,
				routes::establishment::update_establishment,
			],
		)
		.register("/", catchers![internal_error, not_found])
		.attach(Shield::default().enable(Hsts::IncludeSubDomains(Duration::new(31536000, 0))))
		.manage(bound_port)
		.attach(PortCapture)
		.launch()
		.await
	{
		log::error!("Error starting web server: {}", e);
	}
}

#[derive(Debug, Clone)]
pub struct BoundPort(pub Arc<Mutex<Option<u16>>>);

struct PortCapture;

#[rocket::async_trait]
impl Fairing for PortCapture {
	fn info(&self) -> Info {
		Info {
			name: "Capture bound port",
			kind: Kind::Liftoff,
		}
	}

	async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
		let port = rocket.config().port;

		let state = rocket
			.state::<BoundPort>()
			.expect("BoundPort state not managed");

		*state.0.lock().unwrap() = Some(port);
	}
}

#[get("/")]
fn root_redirect() -> Redirect {
	Redirect::to(uri!("/v1/rapidoc"))
}

#[catch(500)]
fn internal_error(_req: &Request<'_>) -> Json<GenericResponse> {
	let response: GenericResponse = Error::generic_500("Unhandled application panic").into();
	Json(response)
}

#[catch(404)]
fn not_found(_req: &Request<'_>) -> Json<GenericResponse> {
	let response: GenericResponse = Error::not_found("This endpoint does not exist").into();
	Json(response)
}
