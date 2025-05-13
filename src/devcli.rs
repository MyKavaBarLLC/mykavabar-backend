#![allow(clippy::all)]

use crate::models::staff_permission::{StaffPermission, StaffPermissionKind};
use crate::{
	error::Error,
	generic::{surrealdb_client, DisplayName, PhoneNumber, UniqueHandle},
	models::{
		establishment::{Coordinate, Establishment, EstablishmentRating, Schedule, TimePeriod},
		review::{Review, ReviewBody, ReviewRating},
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
use std::{
	collections::{HashMap, HashSet},
	str::FromStr,
};
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
	// One-time use. Remove after launch
	Migrate,
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
			Command::Migrate => "Run the database migration.",
		}
		.to_owned()
	}

	fn args(&self) -> Vec<&str> {
		match self {
			Command::Help => vec![],
			Command::State => vec![],
			Command::Get => vec!["<path>"],
			Command::Post => vec!["<path>", "[body]"],
			Command::Delete => vec!["<path>", "[body]"],
			Command::ClearDatabase => vec![],
			Command::Init => vec![],
			Command::Test => vec![],
			Command::Migrate => vec![],
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
		Command::Migrate => {
			if let Err(e) = migrate().await {
				log::error!("Error migrating data: {}", e);
			} else {
				log::info!(
					"Data migrated successfully. Relaunch to reinitialize CLI User. Exiting..."
				);

				std::process::exit(0);
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
		rating: EstablishmentRating::new(480)?,
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
		address: "123 Banyan St, Miami, FL 33101".to_string(),
		phone_number: Some(PhoneNumber::new("+13055551234")?),
	}
	.db_create(&client)
	.await?;

	// Kava Bar 2
	Establishment {
		display_name: DisplayName::new("Awa Awakening Bar")?,
		handle: UniqueHandle::new("awa_awakening").await?,
		coordinate: Coordinate::new(28.5383, -81.3792)?, // Orlando, FL
		rating: EstablishmentRating::new(450)?,
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
		address: "456 Awa Ave, Orlando, FL 32801".to_string(),
		phone_number: Some(PhoneNumber::new("+14075551234")?),
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

	// Cascade delete handles the Staff records

	Ok(())
}

////////////// DELETE THIS AFTER MIGRATION //////////////
// MIGRATOR //

/*

== bar_staff ==
id SERIAL PRIMARY KEY
bar_id INTEGER NOT NULL
user_id INTEGER NOT NULL
hire_date TIMESTAMP NOT NULL DEFAULT now()
is_active BOOLEAN NOT NULL DEFAULT true
position TEXT NOT NULL DEFAULT 'kavatender'::text
notes TEXT
created_at TIMESTAMP NOT NULL DEFAULT now()
updated_at TIMESTAMP

== kava_bars ==
id SERIAL PRIMARY KEY
name TEXT NOT NULL
address TEXT NOT NULL
phone TEXT
hours JSONB
place_id TEXT UNIQUE
rating NUMERIC(3, 2) NOT NULL DEFAULT 0.00
location JSONB
owner_id INTEGER
is_sponsored BOOLEAN DEFAULT false
created_at TIMESTAMP NOT NULL DEFAULT now()
virtual_tour_url TEXT
google_photos JSONB DEFAULT '[]'::jsonb
last_verified TIMESTAMP
verification_status TEXT
business_status TEXT
data_completeness_score NUMERIC(3, 2) DEFAULT 0.00
is_verified_kava_bar BOOLEAN DEFAULT false
verification_notes TEXT

== reviews ==
id SERIAL PRIMARY KEY
user_id INTEGER
bar_id INTEGER
rating INTEGER NOT NULL
content TEXT NOT NULL
upvotes INTEGER DEFAULT 0
created_at TIMESTAMP NOT NULL DEFAULT now()

== users ==
id SERIAL PRIMARY KEY
username TEXT UNIQUE NOT NULL
password TEXT NOT NULL
points INTEGER NOT NULL DEFAULT 0
is_admin BOOLEAN NOT NULL DEFAULT false
created_at TIMESTAMP NOT NULL DEFAULT now()
square_customer_id TEXT
email TEXT NOT NULL
push_subscription JSONB
phone_number TEXT
is_phone_verified BOOLEAN NOT NULL DEFAULT false
role user_role NOT NULL DEFAULT 'regular_user'::user_role
status user_status NOT NULL DEFAULT 'active'::user_status
last_login_at TIMESTAMP
status_changed_at TIMESTAMP
status_changed_by INTEGER
updated_at TIMESTAMP
reset_password_token TEXT
reset_password_expires TIMESTAMP
first_name TEXT NOT NULL
last_name TEXT NOT NULL
profile_photo_url TEXT

*/

async fn migrate() -> Result<(), Error> {
	println!("Clearing database...");
	clear_database().await?;
	println!("Database cleared.");

	let client = surrealdb_client().await?;

	let bar_staff_v: Vec<Value> =
		serde_json::from_reader(std::fs::File::open("./migrate/bar_staff.json").unwrap())?;

	let kava_bars_v: Vec<Value> =
		serde_json::from_reader(std::fs::File::open("./migrate/kava_bars.json").unwrap())?;

	let reviews_v: Vec<Value> =
		serde_json::from_reader(std::fs::File::open("./migrate/reviews.json").unwrap())?;

	let users_v: Vec<Value> =
		serde_json::from_reader(std::fs::File::open("./migrate/users.json").unwrap())?;

	let mut id_map_establishments = HashMap::new();
	let mut id_map_users = HashMap::new();
	let mut staff_set = HashSet::new();

	let mut discriminator = 1;

	for user in users_v {
		println!("Migrating user: {}", user["username"].as_str().unwrap());

		let phone_number = match user["phone_number"].as_str() {
			Some(s) => {
				if s.is_empty() {
					None
				} else {
					Some(PhoneNumber::new(&normalize_us_phone(s))?)
				}
			}
			None => None,
		};

		User {
			uuid: {
				let uuid = SsUuid::new();
				id_map_users.insert(user["id"].as_u64().unwrap(), uuid.clone());
				uuid
			},
			avatar: None,
			display_name: {
				let name = user["username"].as_str().unwrap();
				let name = name.trim();
				let name = cut_if_longer_than_64(name);
				let name = name.trim();
				DisplayName::new(&name)?
			},
			username: {
				let name = user["username"].as_str().unwrap();
				let name = name.trim();
				let name = cut_if_longer_than_64(name);
				let name = name.trim();
				let name = to_handle(name);
				match UniqueHandle::new(&name).await {
					Ok(handle) => handle,
					Err(_) => {
						let name = format!("{}_", name);
						UniqueHandle::new(&name).await.unwrap()
					}
				}
			},
			first_name: {
				if let Some(s) = user["first_name"].as_str() {
					if s.is_empty() {
						None
					} else {
						Some(s.to_string())
					}
				} else {
					None
				}
			},
			last_name: {
				if let Some(s) = user["last_name"].as_str() {
					if s.is_empty() {
						None
					} else {
						Some(s.to_string())
					}
				} else {
					None
				}
			},
			email: {
				let email = user["email"].as_str().unwrap();
				let email = email.trim();
				if email.is_empty() {
					println!(
						"Skipping user {}: no email",
						user["username"].as_str().unwrap()
					);
					continue;
				}
				crate::generic::EmailAddress::new(email)?
			},
			password_hash: { crate::generic::HashedString::new(&generate_password(32))? },
			is_admin: false,
			phone_number: phone_number,
		}
		.db_create(&client)
		.await?;
	}

	for bar_v in kava_bars_v {
		println!("Migrating bar: {}", bar_v["name"].as_str().unwrap());

		let location_v = match &bar_v["location"] {
			serde_json::Value::String(s) => {
				println!(
					"Skipping bar {}: invalid location",
					bar_v["name"].as_str().unwrap()
				);
				continue;
			}
			other => other.clone(),
		};

		let lat = location_v["lat"].as_f64().unwrap();
		let lng = location_v["lng"].as_f64().unwrap();

		Establishment {
			uuid: {
				let uuid = SsUuid::new();
				id_map_establishments.insert(bar_v["id"].as_u64().unwrap(), uuid.clone());
				uuid
			},
			display_name: {
				let name = cut_if_longer_than_64(bar_v["name"].as_str().unwrap());
				let name = name.trim();
				DisplayName::new(&name)?
			},
			handle: {
				match UniqueHandle::new(&to_handle(bar_v["name"].as_str().unwrap())).await {
					Ok(handle) => handle,
					Err(_) => {
						let name = format!(
							"{}_{}",
							to_handle(bar_v["name"].as_str().unwrap()),
							discriminator
						);
						discriminator += 1;
						UniqueHandle::new(&name).await.unwrap()
					}
				}
			},
			coordinate: Coordinate::new(lat, lng)?,
			rating: {
				let rating_str = bar_v["rating"].as_str().unwrap();
				let rating_f32 = rating_str.parse::<f32>().unwrap();
				let rating_u16 = (rating_f32 * 100.0) as u16;
				EstablishmentRating::new(rating_u16)?
			},
			schedule: {
				match bar_v["hours"].as_array() {
					Some(arr) => parse_hours(arr),
					None => Schedule::default(),
				}
			},
			address: bar_v["address"].as_str().unwrap().to_string(),

			phone_number: {
				if let Some(s) = bar_v["phone"].as_str() {
					if s.is_empty() {
						None
					} else {
						Some(PhoneNumber::new(&normalize_us_phone(
							bar_v["phone"].as_str().unwrap(),
						))?)
					}
				} else {
					None
				}
			},
		}
		.db_create(&client)
		.await?;

		// get owner_id if set
		let owner_id = bar_v["owner_id"].as_u64();
		if let Some(owner_id) = owner_id {
			let owner_uuid = id_map_users.get(&owner_id).unwrap();

			let staff_uuid = SsUuid::new();

			Staff {
				uuid: staff_uuid.clone(),
				user: owner_uuid.clone(),
				establishment: id_map_establishments
					.get(&bar_v["id"].as_u64().unwrap())
					.unwrap()
					.clone(),
			}
			.db_create(&client)
			.await?;

			StaffPermission {
				uuid: SsUuid::new(),
				staff: staff_uuid,
				kind: StaffPermissionKind::Admin,
			}
			.db_create(&client)
			.await?;

			staff_set.insert((owner_id, bar_v["id"].as_u64().unwrap()));
		}
	}

	for staff in bar_staff_v {
		if staff_set.contains(&(
			staff["user_id"].as_u64().unwrap(),
			staff["bar_id"].as_u64().unwrap(),
		)) {
			println!("Skipping existing staff: {}", staff["user_id"]);
			continue;
		}

		println!("Migrating staff: {}", staff["user_id"]);

		let user_id = staff["user_id"].as_u64().unwrap();
		let bar_id = staff["bar_id"].as_u64().unwrap();

		let user_uuid = id_map_users.get(&user_id).unwrap();
		let bar_uuid = id_map_establishments.get(&bar_id).unwrap();

		Staff {
			uuid: SsUuid::new(),
			user: user_uuid.clone(),
			establishment: bar_uuid.clone(),
		}
		.db_create(&client)
		.await?;
	}

	for review in reviews_v {
		println!("Migrating review: {}", review["user_id"]);

		let user_id = review["user_id"].as_u64().unwrap();
		let bar_id = review["bar_id"].as_u64().unwrap();

		let user_uuid = id_map_users.get(&user_id).unwrap();
		let bar_uuid = id_map_establishments.get(&bar_id).unwrap();

		Review {
			uuid: SsUuid::new(),
			user: user_uuid.clone(),
			establishment: bar_uuid.clone(),
			rating: ReviewRating::new(review["rating"].as_u64().unwrap() as u8)?,
			body: {
				let body = review["content"].as_str().unwrap();
				let body = body.to_string();
				let body = body.trim();
				if body.is_empty() {
					None
				} else {
					Some(ReviewBody::new(body.to_string())?)
				}
			},
		}
		.db_create(&client)
		.await?;
	}

	Ok(())
}

fn cut_if_longer_than_64(s: &str) -> String {
	if s.len() > 64 {
		s[0..64].to_string()
	} else {
		s.to_string()
	}
}

fn to_handle(display_name: &str) -> String {
	let display_name = display_name.trim();
	let s: String = display_name
		.to_lowercase()
		.chars()
		.map(|c| {
			if c.is_ascii_lowercase() || c.is_ascii_digit() {
				c
			} else {
				'_'
			}
		})
		.collect();

	let s = collapse_underscores(&s);
	let s = cut_if_longer_than_64(&s);
	s
}

fn collapse_underscores(s: &str) -> String {
	let mut result = String::with_capacity(s.len());
	let mut prev_char = '\0';

	for c in s.chars() {
		if c != '_' || prev_char != '_' {
			result.push(c);
		}
		prev_char = c;
	}

	result
}

fn parse_hours(s: &[Value]) -> Schedule {
	fn parse_time(s: &str) -> u16 {
		let s = s.trim();

		let (time, am_pm) = s.split_at(s.len() - 2);
		let am_pm = am_pm.to_lowercase();
		let (hour, minute) = if let Some((h, m)) = time.trim().split_once(':') {
			(
				h.trim().parse::<u16>().unwrap(),
				m.trim().parse::<u16>().unwrap(),
			)
		} else {
			(time.trim().parse::<u16>().unwrap(), 0)
		};

		let hour = match am_pm.as_str() {
			"am" => {
				if hour == 12 {
					0
				} else {
					hour
				}
			}
			"pm" => {
				if hour != 12 {
					hour + 12
				} else {
					12
				}
			}
			_ => hour,
		};

		hour * 60 + minute
	}

	fn parse_period(s: &str) -> Vec<TimePeriod> {
		let s = s.trim();

		// formats like "Sunday: 4:00 - 9:00 PM" which are ambiguous
		if s.contains("0 –") {
			return vec![];
		}
		if s.contains("0 -") {
			return vec![];
		}
		if s.contains("0 –") {
			return vec![];
		}

		if s.eq_ignore_ascii_case("closed") {
			return vec![];
		}
		if s.eq_ignore_ascii_case("open 24 hours") {
			return vec![TimePeriod::new(0, 1440).unwrap()];
		}

		let delimiter = if s.contains(" - ") {
			" - "
		} else if s.contains(" – ") {
			" – "
		} else if s.contains(" – ") {
			" – "
		} else {
			panic!("unknown hour format")
		};

		let (start_str, end_str) = s.split_once(delimiter).unwrap();

		let start = parse_time(start_str);
		let mut end = parse_time(end_str);
		if end <= start {
			end += 1440;
		}

		vec![TimePeriod::new(start, end).unwrap()]
	}

	let mut mon = vec![];
	let mut tue = vec![];
	let mut wed = vec![];
	let mut thu = vec![];
	let mut fri = vec![];
	let mut sat = vec![];
	let mut sun = vec![];

	for entry in s {
		let line = entry.as_str().unwrap_or_default();
		let Some((day, times)) = line.split_once(": ") else {
			continue;
		};
		let periods = parse_period(times);

		match day {
			"Monday" => mon = periods,
			"Tuesday" => tue = periods,
			"Wednesday" => wed = periods,
			"Thursday" => thu = periods,
			"Friday" => fri = periods,
			"Saturday" => sat = periods,
			"Sunday" => sun = periods,
			_ => {}
		}
	}

	Schedule {
		mon,
		tue,
		wed,
		thu,
		fri,
		sat,
		sun,
	}
}

fn normalize_us_phone(input: &str) -> String {
	let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
	if digits.len() == 10 {
		format!("+1{}", digits)
	} else if digits.len() == 11 && digits.starts_with('1') {
		format!("+{}", digits)
	} else {
		panic!("Invalid phone number format: {}", input)
	}
}
