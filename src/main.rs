mod dbrecord;
mod error;
mod generic;
mod jobs;
mod models;
mod routes;
mod test_init;
mod web;

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

	web::start_web().await;
	log::info!("Shutting down...");
}
