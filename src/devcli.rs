use crate::{
	generic::surrealdb_client,
	models::user::{Role, User},
	routes::token::{token_json, TokenRequest},
	web::BoundPort,
};
use rand::rngs::OsRng;
use rustyline::{error::ReadlineError, DefaultEditor};
use serde::Serialize;
use serde_json::{json, Value};
use std::str::FromStr;
use strum::{AsRefStr, EnumIter, EnumString, IntoEnumIterator};
use surreal_socket::dbrecord::DBRecord;

pub async fn run(bound_port: BoundPort) {
	tokio::time::sleep(tokio::time::Duration::from_secs(2)).await; // Let Rocket run
	let mut state = State::default();
	log::info!("Dev CLI started. Type 'help' for a list of commands.");
	state.bearer_token = initial_login().await;
	let mut editor = DefaultEditor::new().expect("Failed to create line editor");

	loop {
		match editor.readline("> ") {
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
				username: "admin".to_owned(),
				display_name: "Admin".to_owned(),
				roles: vec![Role::Admin],
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
