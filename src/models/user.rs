use crate::generic::surrealdb_client;
use crate::{
	error::Error, generic::HashedString, models::session::Session,
	routes::users::RegistrationRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rocket::http::Status;
use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};
use surreal_socket::dbrecord::SsUuid;
use surreal_socket::dbrecord::{DBRecord, Expirable};

const NAME_MIN_LENGTH: usize = 2;
const NAME_MAX_LENGTH: usize = 32;
const PASSWORD_MIN_LENGTH: usize = 8;

#[derive(Serialize, Deserialize)]
pub struct User {
	pub uuid: SsUuid<User>,
	pub username: String,
	pub display_name: String,
	pub password_hash: HashedString,
	pub roles: Vec<Role>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl Default for User {
	fn default() -> Self {
		Self {
			uuid: SsUuid::new(),
			username: "".to_owned(),
			display_name: "".to_owned(),
			password_hash: Default::default(),
			roles: vec![],
			created_at: Utc::now(),
			updated_at: Utc::now(),
		}
	}
}

#[derive(Serialize, Deserialize, PartialEq, EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum Role {
	Admin,
}

impl Role {
	pub fn all() -> Vec<Self> {
		Role::iter().collect()
	}
}

#[async_trait]
impl DBRecord for User {
	fn table() -> &'static str {
		"users"
	}

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}

	fn use_trash() -> bool {
		true
	}
}

impl User {
	/// Create a new User and persist it to the database.
	///
	/// The associated Registration will be deleted.
	///
	/// Default values are specified here.
	pub async fn register(registration_request: &RegistrationRequest) -> Result<Self, Error> {
		let username = Self::validate_username_requirements(&registration_request.username)?;

		if User::db_search_one(&surrealdb_client().await?, "username", username.clone())
			.await?
			.is_some()
		{
			return Err(Error::new(
				Status::BadRequest,
				"Username unavailable.",
				None,
			));
		};

		Self::verify_password_requirements(&registration_request.password)?;

		let user = Self {
			uuid: SsUuid::new(),
			username,
			display_name: Self::validate_displayname_requirements(
				&registration_request.display_name,
			)?,
			password_hash: HashedString::new(&registration_request.password)?,
			created_at: Utc::now(),
			updated_at: Utc::now(),
			..Default::default()
		};

		user.db_create(&surrealdb_client().await?).await?;

		Ok(user)
	}

	pub fn has_role(&self, role: &Role) -> bool {
		self.roles.contains(role)
	}

	pub fn verify_password(&self, password: &str) -> Result<(), Error> {
		if self.password_hash.verify(password)? {
			Ok(())
		} else {
			Err(Error::generic_401())
		}
	}

	pub async fn get_session_from_refresh_token(
		&self,
		refresh_token: &str,
	) -> Result<Option<Session>, Error> {
		let sessions: Vec<Session> =
			Session::db_search(&surrealdb_client().await?, "user", self.uuid.clone()).await?;

		for session in sessions {
			if session.refresh_token_hash.verify(refresh_token)? {
				if !session.is_expired()? {
					return Ok(Some(session));
				} else {
					session.db_delete(&surrealdb_client().await?).await?;
					continue;
				}
			}
		}

		Ok(None)
	}

	pub fn validate_username_requirements(username: &str) -> Result<String, Error> {
		Self::validate_name_length(username)?;

		if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
			return Err(Error::new(
				Status::BadRequest,
				"Username must contain only alphanumeric characters and underscores.",
				None,
			));
		}

		Ok(username.to_lowercase())
	}

	pub fn validate_displayname_requirements(displayname: &str) -> Result<String, Error> {
		Self::validate_name_length(displayname)?;
		Ok(displayname.trim().to_owned())
	}

	fn validate_name_length(name: &str) -> Result<(), Error> {
		if name.len() < NAME_MIN_LENGTH {
			return Err(Error::new(
				Status::BadRequest,
				&format!("Name must be at least {} characters long.", NAME_MIN_LENGTH),
				None,
			));
		}

		if name.len() > NAME_MAX_LENGTH {
			return Err(Error::new(
				Status::BadRequest,
				&format!("Name must be at most {} characters long.", NAME_MAX_LENGTH),
				None,
			));
		}

		Ok(())
	}

	fn verify_password_requirements(password: &str) -> Result<(), Error> {
		if password.len() < PASSWORD_MIN_LENGTH {
			return Err(Error::new(
				Status::BadRequest,
				&format!(
					"Password must be at least {} characters long.",
					PASSWORD_MIN_LENGTH
				),
				None,
			));
		}

		Ok(())
	}

	/// Verify password requirements, update the password, and persist it to the database.
	pub async fn set_password(&mut self, password: &str) -> Result<(), Error> {
		Self::verify_password_requirements(password)?;
		self.password_hash = HashedString::new(password)?;

		self.db_update_field(
			&surrealdb_client().await?,
			"password_hash",
			&self.password_hash,
		)
		.await?;

		Ok(())
	}
}
