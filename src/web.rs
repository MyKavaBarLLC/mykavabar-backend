use crate::routes;
use rocket::{
	fairing::{Fairing, Info, Kind},
	fs::{relative, NamedFile},
	serde::json::Json,
	shield::{Hsts, Shield},
	time::Duration,
	Orbit, Rocket,
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
				static_pages,
				version,
				routes::token::token_json,
				routes::token::token_form,
				routes::check_token::check_token,
				routes::users::register,
				routes::pages::admin::admin,
				routes::users::change_password,
				routes::users::get_users,
				routes::users::update_user,
				routes::users::delete_user,
			],
		)
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
