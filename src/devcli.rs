use crate::{
	error::Error,
	generic::{surrealdb_client, DisplayName, UniqueHandle},
	models::{
		establishment::{Coordinate, Establishment, Rating, Schedule, TimePeriod},
		staff::Staff,
		user::User,
	},
	routes::token::{token_json, TokenRequest},
	web::BoundPort,
};
use rand::rngs::OsRng;
use rustyline::{error::ReadlineError, DefaultEditor};
use serde::Serialize;
use serde_json::{json, Value};
use std::str::FromStr;
use strum::{AsRefStr, EnumIter, EnumString, IntoEnumIterator};
use surreal_socket::dbrecord::{DBRecord, SsUuid};

pub async fn test_function() -> Result<(), Error> {
	// Test things here. Don't version changes.

	Ok(())
}

pub async fn run(bound_port: BoundPort) {
	tokio::time::sleep(tokio::time::Duration::from_secs(2)).await; // Let Rocket run
	let mut state = State::default();
	log::info!("Dev CLI started. Type 'help' for a list of commands.");
	state.bearer_token = initial_login().await;
	let mut editor = DefaultEditor::new().expect("Failed to create line editor");

	loop {
		match editor.readline("") {
			Ok(line) => {
				if state.port == 0 {
					state.port = bound_port.0.lock().unwrap().unwrap_or_default();
				}

				let line = line.trim();
				editor.add_history_entry(line.to_owned()).ok();
				let mut parts = line.split_whitespace();

				if let Some(command) = parts.next() {
					match Command::from_str(command) {
						Ok(cmd) => {
							let args: Vec<String> = parts.map(|s| s.to_string()).collect();
							handle_command(&state, cmd, args).await
						}
						Err(_) => eprintln!("Invalid command: {}", command),
					}
				}
			}
			Err(err) => {
				match err {
					ReadlineError::Interrupted => {}
					_ => {
						log::error!("Error reading line: {err}");
					}
				}

				break;
			}
		}
	}
}

#[derive(Serialize, Default)]
struct State {
	bearer_token: String,
	port: u16,
}

#[derive(Debug, EnumString, EnumIter, AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum Command {
	Help,
	State,
	Get,
	Post,
	Delete,
	ClearDatabase,
	Init,
	Test,
}

impl Command {
	fn info(&self) -> String {
		match self {
			Command::Help => "Show this help message",
			Command::State => "Show current state data",
			Command::Get => "Send a GET request to /v1/{path}, including the Bearer token header",
			Command::Post => "Send a POST request to /v1/{path}, including the Bearer token header",
			Command::Delete => {
				"Send a DELETE request to /v1/{path}, including the Bearer token header"
			}
			Command::ClearDatabase => "Clear the database and exit",
			Command::Init => "Create test data",
			Command::Test => {
				"Run test_function for quick ad-hoc code testing. Does nothing by default."
			}
		}
		.to_owned()
	}

	fn args(&self) -> Vec<String> {
		match self {
			Command::Help => vec![],
			Command::State => vec![],
			Command::Get => vec!["<path>".to_owned()],
			Command::Post => vec!["<path> [body]".to_owned()],
			Command::Delete => vec!["<path> [body]".to_owned()],
			Command::ClearDatabase => vec![],
			Command::Init => vec![],
			Command::Test => vec![],
		}
	}
}

async fn handle_command(state: &State, cmd: Command, args: Vec<String>) {
	match cmd {
		Command::Help => {
			println!("Available commands:");
			for command in Command::iter() {
				let args = command.args();

				let args_str = if args.is_empty() {
					String::new()
				} else {
					format!(" {}", args.join(" "))
				};

				println!("  {}{}: {}", command.as_ref(), args_str, command.info());
			}
		}
		Command::State => {
			println!("{}", serde_json::to_string_pretty(state).unwrap());
		}
		Command::Get => {
			request_command(state, RequestMethod::Get, args).await;
		}
		Command::Post => {
			request_command(state, RequestMethod::Post, args).await;
		}
		Command::Delete => {
			request_command(state, RequestMethod::Delete, args).await;
		}
		Command::ClearDatabase => {
			if let Err(e) = clear_database().await {
				log::error!("Error clearing database: {}", e);
			} else {
				log::info!("Database cleared. Relaunch to reinitialize CLI User. Exiting...");
				std::process::exit(0);
			}
		}
		Command::Init => {
			if let Err(e) = create_test_data().await {
				log::error!("Error creating test data: {}", e);
			} else {
				log::info!("Test data created successfully.");
			}
		}
		Command::Test => {
			if let Err(e) = test_function().await {
				log::error!("test_function returned an error: {}", e);
			} else {
				log::info!("test_function executed successfully.");
			}
		}
	}
}

async fn request_command(state: &State, method: RequestMethod, args: Vec<String>) {
	let reqwest_client = reqwest::Client::new();

	let url = match args.first() {
		Some(path) => {
			format!("http://localhost:{}/v1/{}", state.port, path)
		}
		None => {
			eprintln!("Missing path argument");
			return;
		}
	};

	let request = match method {
		RequestMethod::Get => reqwest_client.get(&url),
		RequestMethod::Post => reqwest_client.post(&url),
		RequestMethod::Delete => reqwest_client.delete(&url),
	};

	let mut request = request.bearer_auth(state.bearer_token.to_owned());

	let sent_body = if method != RequestMethod::Get && args.len() > 1 {
		let body = args[1..].join(" ");

		if !body.is_empty() {
			request = request
				.body(body.to_owned())
				.header("Content-Type", "application/json");

			Some(body)
		} else {
			None
		}
	} else {
		None
	};

	let response = request.send().await.unwrap();
	let status = response.status().as_u16();
	let text = response.text().await.unwrap();

	let body = match serde_json::from_str::<Value>(&text) {
		Ok(value) => serde_json::to_string_pretty(&value).unwrap_or(text),
		Err(_) => text,
	};

	println!("> {} {}", method.as_ref().to_uppercase(), url);

	if let Some(sent_body) = &sent_body {
		println!("> Body:\n{}", sent_body);
	}

	println!("\n< {}", status);
	println!("< Response:\n{}", body);
}

/// Attempt to log in as the default CLI user, otherwise create the user.
async fn initial_login() -> String {
	let client = surrealdb_client().await.unwrap();
	let password = generate_password(64);

	let mut admin = match User::db_search_one(&client, "username", "admin".to_string())
		.await
		.unwrap()
	{
		Some(user) => user,
		None => {
			let admin = User {
				username: UniqueHandle::new("admin").await.unwrap(),
				display_name: DisplayName::new("CLI Admin").unwrap(),
				is_admin: true,
				..Default::default()
			};

			admin.db_create(&client).await.unwrap();
			admin
		}
	};

	admin.set_password(&password).await.unwrap();

	let token_request: TokenRequest = serde_json::from_value(json!({
		"grant_type": "password",
		"username": "admin",
		"password": password,
	}))
	.unwrap();

	let response = match token_json(rocket::serde::json::Json(token_request)).await {
		Ok(response) => response,
		Err(_) => {
			log::error!("Error logging into CLI Admin");
			return String::new();
		}
	};

	let response_string = serde_json::to_string(&response.into_inner()).unwrap();
	let response_value = serde_json::from_str::<Value>(&response_string).unwrap();

	let token = response_value
		.get("access_token")
		.and_then(Value::as_str)
		.unwrap_or_default();

	token.to_owned()
}

pub fn generate_password(length: usize) -> String {
	rand::distributions::DistString::sample_string(
		&rand::distributions::Alphanumeric,
		&mut OsRng,
		length,
	)
}

#[derive(Debug, EnumString, PartialEq, AsRefStr)]
enum RequestMethod {
	Get,
	Post,
	Delete,
}

/// Test data by ChatGPT
async fn create_test_data() -> Result<(), Error> {
	let client = surrealdb_client().await?;
	let banyan_uuid = SsUuid::new();
	let awa_uuid = SsUuid::new();

	// Kava Bar 1
	Establishment {
		display_name: DisplayName::new("Banyan Root Kava Lounge")?,
		handle: UniqueHandle::new("banyan_root").await?,
		coordinate: Coordinate::new(25.7617, -80.1918)?, // Miami, FL
		rating: Rating::new(480)?,
		uuid: banyan_uuid.clone(),
		schedule: Schedule {
			sun: vec![TimePeriod::new(1080, 1380)?],
			mon: vec![TimePeriod::new(1020, 1380)?],
			tue: vec![TimePeriod::new(1020, 1380)?],
			wed: vec![TimePeriod::new(1020, 1380)?],
			thu: vec![TimePeriod::new(1020, 1380)?],
			fri: vec![TimePeriod::new(1020, 1439)?],
			sat: vec![TimePeriod::new(1020, 1439)?],
		},
	}
	.db_create(&client)
	.await?;

	// Kava Bar 2
	Establishment {
		display_name: DisplayName::new("Awa Awakening Bar")?,
		handle: UniqueHandle::new("awa_awakening").await?,
		coordinate: Coordinate::new(28.5383, -81.3792)?, // Orlando, FL
		rating: Rating::new(450)?,
		uuid: awa_uuid.clone(),
		schedule: Schedule {
			sun: vec![TimePeriod::new(360, 720)?, TimePeriod::new(960, 1260)?],
			mon: vec![TimePeriod::new(300, 720)?, TimePeriod::new(960, 1260)?],
			tue: vec![TimePeriod::new(300, 720)?, TimePeriod::new(960, 1260)?],
			wed: vec![TimePeriod::new(300, 720)?, TimePeriod::new(960, 1260)?],
			thu: vec![TimePeriod::new(300, 720)?, TimePeriod::new(960, 1260)?],
			fri: vec![TimePeriod::new(300, 720)?, TimePeriod::new(960, 1260)?],
			sat: vec![TimePeriod::new(360, 720)?, TimePeriod::new(960, 1260)?],
		},
	}
	.db_create(&client)
	.await?;

	// User 1 - works only at Banyan Root
	let kai = User {
		username: UniqueHandle::new("kai_wave").await?,
		display_name: DisplayName::new("Kai Wave")?,
		uuid: SsUuid::new(),
		..Default::default()
	}
	.db_create(&client)
	.await?;

	Staff {
		uuid: SsUuid::new(),
		establishment: banyan_uuid.clone(),
		user: kai.uuid.clone(),
	}
	.db_create(&client)
	.await?;

	// User 2 - works at both bars
	let lani = User {
		username: UniqueHandle::new("lani_chill").await?,
		display_name: DisplayName::new("Lani Chill")?,
		uuid: SsUuid::new(),
		..Default::default()
	}
	.db_create(&client)
	.await?;

	Staff {
		uuid: SsUuid::new(),
		establishment: banyan_uuid.clone(),
		user: lani.uuid.clone(),
	}
	.db_create(&client)
	.await?;

	Staff {
		uuid: SsUuid::new(),
		establishment: awa_uuid.clone(),
		user: lani.uuid.clone(),
	}
	.db_create(&client)
	.await?;

	// User 3 - works only at Awa Awakening
	let mika = User {
		username: UniqueHandle::new("mika_sunset").await?,
		display_name: DisplayName::new("Mika Sunset")?,
		uuid: SsUuid::new(),
		..Default::default()
	}
	.db_create(&client)
	.await?;

	Staff {
		uuid: SsUuid::new(),
		establishment: awa_uuid,
		user: mika.uuid.clone(),
	}
	.db_create(&client)
	.await?;

	Ok(())
}

async fn clear_database() -> Result<(), Error> {
	let client = surrealdb_client().await?;

	let users = User::db_all(&client).await?;
	for user in users {
		user.db_delete(&client).await?;
	}

	let establishments = Establishment::db_all(&client).await?;
	for establishment in establishments {
		establishment.db_delete(&client).await?;
	}

	let staff = Staff::db_all(&client).await?;
	for staff in staff {
		staff.db_delete(&client).await?;
	}

	Ok(())
}
