use crate::routes;
use rocket::{
	fs::{relative, NamedFile},
	serde::json::Json,
	shield::{Hsts, Shield},
	time::Duration,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

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

pub async fn start_web() {
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
		.launch()
		.await
	{
		log::error!("Error starting web server: {}", e);
	}
}
