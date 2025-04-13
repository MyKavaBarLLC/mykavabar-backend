use std::sync::{Arc, Mutex};
use web::BoundPort;

mod error;
mod generic;
mod jobs;
mod models;
mod routes;
mod test_init;
mod web;

#[cfg(debug_assertions)]
mod devcli;

#[tokio::main]
async fn main() {
	env_logger::builder()
		.filter_level(log::LevelFilter::Info)
		.filter_module("tracing::span", log::LevelFilter::Warn)
		.filter_module("serenity", log::LevelFilter::Warn)
		.init();

	generic::Environment::load_path("config.toml");
	let args: Vec<String> = std::env::args().collect();

	if args.contains(&"test".to_string()) {
		crate::test_init::test_init().await;
		return;
	}

	log::info!("Starting...");
	jobs::Job::spawn_all();

	let bound_bort = BoundPort(Arc::new(Mutex::new(None)));
	let bound_bort_clone = bound_bort.clone();

	#[cfg(debug_assertions)]
	let devcli_fut = tokio::spawn(async {
		crate::devcli::run(bound_bort_clone).await;
	});

	#[cfg(not(debug_assertions))]
	let devcli_fut = tokio::spawn(async {
		// Dummy future that never completes
		futures::future::pending::<()>().await;
	});

	let web_fut = tokio::spawn(async {
		web::start_web(bound_bort).await;
	});

	tokio::select! {
		_ = devcli_fut => {
			log::info!("Dev CLI exited.");
		}
		_ = web_fut => {
			log::info!("Web server exited.");
		}
	}

	log::info!("Shutting down...");
}
