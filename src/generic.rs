use crate::{
	dbrecord::{DBRecord, SQLCommand},
	error::Error,
	models::session::Session,
};
use argon2::Argon2;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use password_hash::{
	rand_core::OsRng, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString,
};
use rocket::{
	http::{HeaderMap, Status},
	request::{FromRequest, Outcome},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, marker::PhantomData};
use surrealdb::{
	engine::remote::ws::Ws,
	opt::auth::Root,
	sql::{Id, Thing, Uuid},
	Surreal,
};

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
		oauth_jwt_secret
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

/// A typed wrapper for the `Thing` object that corresponds to an ID in Surreal.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct UUID<T>(Thing, PhantomData<T>);

impl<T: DBRecord> Clone for UUID<T> {
	fn clone(&self) -> Self {
		Self(self.0.to_owned(), PhantomData)
	}
}

impl<T: DBRecord> From<Thing> for UUID<T> {
	fn from(thing: Thing) -> Self {
		UUID(thing, PhantomData)
	}
}

impl<T> UUID<T>
where
	T: DBRecord,
{
	/// Get the Thing (`surrealdb::sql::thing::Thing`) from the UUID.
	pub fn thing(&self) -> Thing {
		self.0.to_owned()
	}

	/// Get the UUID as a string.
	pub fn uuid_string(&self) -> String {
		match &self.0.id {
			Id::Uuid(uuid) => uuid.0.to_string(),
			Id::String(s) => s.to_owned(),
			_ => panic!("Invalid UUID type"),
		}
	}

	/// Create a new UUID with a random ID for the given table.
	pub fn new() -> Self {
		Thing::from((T::table().to_owned(), Id::from(Uuid::new_v4()))).into()
	}

	/// Get the object associated with the UUID.
	///
	/// Returns an `Error` if SurrealDB unexpectedly fails.
	///
	/// If a missing object should not result in an error, use `object_opt()` instead.
	#[allow(dead_code)]
	pub async fn object(&self) -> Result<T, Error>
	where
		T: DBRecord,
	{
		let opt = self.object_opt().await?;
		let obj = opt.ok_or_else(|| Error::generic_500("Associated object not found"))?;
		Ok(obj)
	}

	/// Get the object associated with the UUID, or `None` if not found.
	pub async fn object_opt(&self) -> Result<Option<T>, Error>
	where
		T: DBRecord,
	{
		let obj: Option<T> = T::db_by_id(&self.uuid_string()).await?;
		Ok(obj)
	}
}

impl<T: DBRecord> Default for UUID<T> {
	fn default() -> Self {
		Thing::from((String::new(), Id::from(String::new()))).into()
	}
}

impl<T: DBRecord> Serialize for UUID<T> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let s = format!("{}:{}", self.0.tb, self.uuid_string());
		serializer.serialize_str(&s)
	}
}

impl<'de, T: DBRecord> Deserialize<'de> for UUID<T> {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct UUIDVisitor<T>(PhantomData<T>);

		impl<T> serde::de::Visitor<'_> for UUIDVisitor<T> {
			type Value = UUID<T>;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				formatter.write_str("a string in the format `table:uuid`")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: serde::de::Error,
			{
				let parts: Vec<&str> = value.splitn(2, ':').collect();
				if parts.len() != 2 {
					return Err(E::custom("expected a string in the format `table:uuid`"));
				}
				Ok(UUID(Thing::from((parts[0], parts[1])), PhantomData))
			}
		}

		deserializer.deserialize_string(UUIDVisitor(PhantomData))
	}
}

impl<T: DBRecord> PartialEq for UUID<T> {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
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

#[async_trait]
pub trait Expirable: DBRecord {
	fn start_time_field() -> &'static str;

	fn expiry_seconds() -> u64;

	fn start_timestamp(&self) -> Result<i64, Error> {
		let value = serde_json::to_value(self)?;
		let start_time_str = value
			.get(Self::start_time_field())
			.ok_or(Error::generic_500(
				"start_time_field() does not match a property in an Expirable",
			))?
			.as_str()
			.ok_or(Error::generic_500(
				"start_time_field() does not match a string in an Expirable",
			))?;

		let start_time = DateTime::parse_from_rfc3339(start_time_str).map_err(|e| {
			Error::generic_500(&format!(
				"Error parsing start_time_field() as RFC3339: {}",
				e
			))
		})?;

		Ok(start_time.timestamp())
	}

	async fn clear_expired() -> Result<(), Error> {
		let earliest_valid_time = Utc::now()
			.checked_sub_signed(Duration::seconds(Self::expiry_seconds() as i64))
			.ok_or(Error::generic_500(
				"Out of bounds datetime in clear_expired()",
			))?;

		Self::db_query(
			SQLCommand::Delete,
			format!("time::unix(type::datetime({}))", Self::start_time_field()),
			'<',
			earliest_valid_time.timestamp(),
		)
		.await?;

		Ok(())
	}

	fn is_expired(&self) -> Result<bool, Error> {
		let now = Utc::now().timestamp();
		let start_time = self.start_timestamp()?;
		Ok(now - start_time > Self::expiry_seconds() as i64)
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
