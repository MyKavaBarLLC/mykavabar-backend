use crate::{
	dbrecord::DBRecord,
	error::Error,
	generic::{Environment, Expirable, HashedString, JwtClaims, UUID},
	models::user::User,
};
use chrono::{DateTime, Utc};
use rocket::http::Status;
use serde::{Deserialize, Serialize};
use surrealdb::sql::Uuid;

pub const ACCESS_TOKEN_EXPIRY_SECONDS: u64 = 60 * 60; // 1 hour
pub const REFRESH_TOKEN_EXPIRY_SECONDS: u64 = 60 * 60 * 24 * 30; // 30 days

#[derive(Serialize, Deserialize)]
pub struct Session {
	pub uuid: UUID<Session>,
	created_at: DateTime<Utc>,
	updated_at: DateTime<Utc>,
	user: UUID<User>,
	pub refresh_token_hash: HashedString,
	pub refresh_token_issued_at: DateTime<Utc>,
}

impl DBRecord for Session {
	fn table() -> &'static str {
		"sessions"
	}

	fn uuid(&self) -> UUID<Self> {
		self.uuid.to_owned()
	}
}

impl Session {
	/// Create a new Session, without persisting it to the database.
	pub fn new(user: &UUID<User>) -> Result<Self, Error> {
		Ok(Self {
			uuid: UUID::new(),
			created_at: Utc::now(),
			updated_at: Utc::now(),
			user: user.to_owned(),
			refresh_token_hash: HashedString::new(&Uuid::new_v4().to_string())?,
			refresh_token_issued_at: Utc::now(),
		})
	}

	/// Verify the access token and return the Session associated with it.
	pub async fn from_access_token(access_token: &str) -> Result<Self, Error> {
		let env = Environment::new();
		let secret = env.oauth_jwt_secret.val();
		let decoding_key = jsonwebtoken::DecodingKey::from_secret(secret.as_ref());

		let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
		validation.set_audience(&["kavacoast.com-session"]);
		validation.set_issuer(&["kavacoast.com"]);

		let token_data =
			jsonwebtoken::decode::<JwtClaims>(access_token, &decoding_key, &validation)
				.map_err(|_| Error::generic_401())?;
		// note: decode() also checks expiration

		let session: Session = Self::db_by_id(&token_data.claims.sub)
			.await?
			.ok_or(Error::generic_401())?;

		Ok(session)
	}

	/// Generate a new refresh token for the session, updating the database and invalidating the previous one.
	pub async fn rotate_refresh_token(&mut self) -> Result<String, Error> {
		let refresh_token = Uuid::new_v4().to_raw();

		self.refresh_token_hash = HashedString::new(&refresh_token)?;
		self.refresh_token_issued_at = Utc::now();

		self.db_update_fields(vec![
			(
				"refresh_token_hash",
				&serde_json::to_value(&self.refresh_token_hash)?,
			),
			(
				"refresh_token_issued_at",
				&serde_json::to_value(self.refresh_token_issued_at)?,
			),
		])
		.await?;

		Ok(refresh_token)
	}

	/// Generate a new access token for the session.
	///
	/// This method does not update the database,
	/// as the token is a stateless JWT.
	pub fn generate_access_token(&self) -> Result<String, Error> {
		let now = chrono::Utc::now().timestamp() as u64;
		let env = Environment::new();

		let claims = JwtClaims {
			sub: self.uuid.uuid_string(),
			exp: now + ACCESS_TOKEN_EXPIRY_SECONDS,
			iat: now,
			iss: "kavacoast.com".to_owned(),
			aud: "kavacoast.com-session".to_owned(),
		};

		let secret = env.oauth_jwt_secret.val();
		let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret.as_ref());

		jsonwebtoken::encode(
			&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
			&claims,
			&encoding_key,
		)
		.map_err(|e| Error::generic_500(&format!("Error encoding new JWT: {:?}", e)))
	}

	pub async fn user(&self) -> Result<User, Error> {
		self.user
			.object_opt()
			.await?
			.ok_or_else(|| Error::new(Status::Unauthorized, "Session user not found", None))
	}
}

impl Expirable for Session {
	fn start_time_field() -> &'static str {
		"refresh_token_issued_at"
	}

	fn expiry_seconds() -> u64 {
		REFRESH_TOKEN_EXPIRY_SECONDS
	}
}
