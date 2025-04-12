use crate::{error::Error, models::session::Session};
use argon2::Argon2;
use password_hash::{
	rand_core::OsRng, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString,
};
use rocket::{
	http::{HeaderMap, Status},
	request::{FromRequest, Outcome},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use surrealdb::{engine::remote::ws::Ws, opt::auth::Root, Surreal};

pub async fn surrealdb_client() -> Result<Surreal<surrealdb::engine::remote::ws::Client>, String> {
	let env = Environment::new();

	let db = Surreal::new::<Ws>(env.surreal_address.val())
		.await
		.map_err(|e| "Error connecting to SurrealDB: ".to_owned() + &e.to_string())?;

	db.signin(Root {
		username: &env.surreal_username.val(),
		password: &env.surreal_password.val(),
	})
	.await
	.map_err(|e| "Error signing in to SurrealDB: ".to_owned() + &e.to_string())?;

	db.use_ns(env.surreal_namespace.val())
		.use_db(env.surreal_database.val())
		.await
		.map_err(|e| "Error using namespace/database: ".to_owned() + &e.to_string())?;

	Ok(db)
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct Environment {
	pub surreal_password: EnvVarKey,
	pub surreal_username: EnvVarKey,
	pub surreal_address: EnvVarKey,
	pub surreal_namespace: EnvVarKey,
	pub surreal_database: EnvVarKey,
	pub oauth_jwt_secret: EnvVarKey,
	pub domain: EnvVarKey,
}

macro_rules! initialize_env {
    ($($field:ident),+) => {
        pub fn initialize_env(&mut self) {
            $(self.$field = EnvVarKey(stringify!($field).to_uppercase());)*
        }
    };
}

impl Environment {
	pub fn new() -> Self {
		let mut env = Self::default();
		env.initialize_env();
		env
	}

	initialize_env!(
		surreal_password,
		surreal_username,
		surreal_address,
		surreal_namespace,
		surreal_database,
		oauth_jwt_secret,
		domain
	);

	pub fn load_path(path: &str) {
		let env: Self =
			confy::load_path(path).unwrap_or_else(|err| panic!("Failed to load {}: {}", path, err));

		let map = env.as_hashmap();

		for (key, value) in map.iter() {
			std::env::set_var(key, &value.0);
		}
	}

	fn as_hashmap(&self) -> HashMap<String, EnvVarKey> {
		let value = serde_json::to_value(self).unwrap();
		let mut map = HashMap::new();

		for (key, value) in value.as_object().unwrap().iter() {
			let value = value.as_str().unwrap();
			map.insert(key.to_string(), EnvVarKey(value.to_string()));
		}

		map
	}
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct EnvVarKey(String);

impl EnvVarKey {
	pub fn val(&self) -> String {
		std::env::var(&self.0)
			.unwrap_or_else(|_| panic!("Missing environment variable: {}", self.0))
	}
}

/// An Argon2 hashed string, hashed with `new()` and verified with `verify()`
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HashedString(String);

impl HashedString {
	/// Hash a string with Argon2 and wrap it in a `HashedString`
	pub fn new(s: &str) -> Result<Self, Error> {
		let salt = SaltString::generate(&mut OsRng);
		let p_bytes = s.as_bytes();

		let hash = Argon2::default()
			.hash_password(p_bytes, &salt)
			.map_err(|e| Error::generic_500(&format!("Argon2 hash error: {:?}", e)))?;

		Ok(HashedString(hash.serialize().to_string()))
	}

	/// Verify a string against the hash, returning `Ok(true)` on match, `Ok(false)` on mismatch, and `Err` on internal errors
	pub fn verify(&self, password: &str) -> Result<bool, Error> {
		let password_hash_string = PasswordHashString::new(&self.0).map_err(|e| {
			Error::generic_500(&format!("Error creating PasswordHashString: {}", e))
		})?;

		let refresh_token_hash = password_hash_string.password_hash();

		Ok(Argon2::default()
			.verify_password(password.as_bytes(), &refresh_token_hash)
			.is_ok())
	}
}

#[derive(Serialize)]
pub struct GenericOkResponse {
	success: bool,
}

impl GenericOkResponse {
	pub fn new() -> Self {
		Self { success: true }
	}
}

impl Default for GenericOkResponse {
	fn default() -> Self {
		Self::new()
	}
}

pub struct BearerToken(Option<String>);

impl BearerToken {
	fn from_headermap(headermap: &HeaderMap) -> Self {
		Self(
			headermap
				.get_one("Authorization")
				.and_then(|header_str| header_str.strip_prefix("Bearer "))
				.map(|token| token.to_owned()),
		)
	}

	/// Validate the token and return the session
	pub async fn validate(&self) -> Result<Session, Error> {
		let token = self.0.as_ref().ok_or(Error::new(
			Status::Unauthorized,
			"Missing Authorization header",
			None,
		))?;

		Session::from_access_token(token).await
	}
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerToken {
	type Error = ();
	async fn from_request(request: &'r rocket::request::Request<'_>) -> Outcome<Self, Self::Error> {
		Outcome::Success(BearerToken::from_headermap(request.headers()))
	}
}

#[derive(Debug, Serialize, Deserialize)]
/// [JWT Claims](https://datatracker.ietf.org/doc/html/rfc7519)
pub struct JwtClaims {
	/// Subject
	///
	/// (Session Id)
	pub sub: String,
	/// Expiration Time
	pub exp: u64,
	/// Issued At
	pub iat: u64,
	/// Issuer
	pub iss: String,
	/// Audience
	pub aud: String,
}
