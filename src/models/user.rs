use crate::generic::{surrealdb_client, DisplayName, HasHandle, UniqueHandle};
use crate::{
	error::Error, generic::HashedString, models::session::Session,
	routes::users::RegistrationRequest,
};
use async_trait::async_trait;
use rocket::http::Status;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::SsUuid;
use surreal_socket::dbrecord::{DBRecord, Expirable};
use surreal_socket::error::SurrealSocketError;

const PASSWORD_MIN_LENGTH: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
	pub uuid: SsUuid<User>,
	pub username: UniqueHandle<User>,
	pub display_name: DisplayName,
	pub password_hash: HashedString,
	pub is_admin: bool,
}

impl HasHandle for User {
	fn handle_field() -> &'static str {
		"username"
	}
}

impl Default for User {
	fn default() -> Self {
		Self {
			uuid: SsUuid::new(),
			username: UniqueHandle::default(),
			display_name: DisplayName::default(),
			password_hash: Default::default(),
			is_admin: false,
		}
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

	async fn pre_delete_hook(&self) -> Result<(), SurrealSocketError> {
		let client = surrealdb_client().await?;
		let sessions = Session::db_search(&client, "user", self.uuid.clone()).await?;

		for session in sessions {
			session.db_delete(&client).await?;
		}

		Ok(())
	}
}

impl User {
	/// Create a new User and persist it to the database.
	///
	/// The associated Registration will be deleted.
	///
	/// Default values are specified here.
	pub async fn register(registration_request: &RegistrationRequest) -> Result<Self, Error> {
		let username = UniqueHandle::new(&registration_request.username).await?;

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
			display_name: DisplayName::new(&registration_request.display_name)?,
			password_hash: HashedString::new(&registration_request.password)?,
			..Default::default()
		};

		user.db_create(&surrealdb_client().await?).await?;

		Ok(user)
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
