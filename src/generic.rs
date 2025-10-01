use crate::{error::Error, models::session::Session};
use argon2::Argon2;
use password_hash::{
    rand_core::OsRng, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString,
};
use rocket::{
    http::{HeaderMap, Status},
    request::{FromRequest, Outcome},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, fmt::Display, marker::PhantomData};
use surreal_socket::dbrecord::DBRecord;
use surrealdb::{engine::remote::ws::Ws, opt::auth::Root, Surreal};
use utoipa::ToSchema;

// Establishment & User names
const NAME_MIN_LENGTH: usize = 2;
const NAME_MAX_LENGTH: usize = 64;

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
            confy::load_path(path).unwrap_or_else(|err| panic!("Failed to load {path}: {err}"));

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
            .map_err(|e| Error::generic_500(&format!("Argon2 hash error: {e:?}")))?;

        Ok(HashedString(hash.serialize().to_string()))
    }

    /// Verify a string against the hash, returning `Ok(true)` on match, `Ok(false)` on mismatch, and `Err` on internal errors
    pub fn verify(&self, password: &str) -> Result<bool, Error> {
        let password_hash_string = PasswordHashString::new(&self.0)
            .map_err(|e| Error::generic_500(&format!("Error creating PasswordHashString: {e}")))?;

        let refresh_token_hash = password_hash_string.password_hash();

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &refresh_token_hash)
            .is_ok())
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

#[derive(Serialize, Deserialize, ToSchema)]
pub struct GenericResponse {
    /// Success status. If true, `error` is null.
    success: bool,
    /// Error description when `success` is false.
    #[schema(example = "Error description")]
    error: Option<String>,
}

impl GenericResponse {
    pub fn success() -> Self {
        GenericResponse {
            success: true,
            error: None,
        }
    }

    pub fn error(message: &str) -> Self {
        GenericResponse {
            success: false,
            error: Some(message.to_owned()),
        }
    }
}

/// Converts an `Error` into a `GenericResponse` with the public description.
///
/// Logs the internal description if set
impl From<Error> for GenericResponse {
    fn from(e: Error) -> Self {
        if let Some(internal_desc) = e.internal_desc {
            log::error!("{internal_desc}");
        }

        GenericResponse {
            success: false,
            error: Some(e.public_desc.to_owned()),
        }
    }
}

impl From<Error> for rocket::response::status::Custom<rocket::serde::json::Json<GenericResponse>> {
    fn from(e: Error) -> Self {
        rocket::response::status::Custom(e.status, rocket::serde::json::Json(e.into()))
    }
}

/// Non-unique display name. Can include spaces and special characters.
#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct DisplayName(String);

/// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
#[derive(Debug, Clone, Default, ToSchema)]
pub struct UniqueHandle<T>(String, PhantomData<T>);

impl DisplayName {
    pub fn new(name: &str) -> Result<Self, Error> {
        let display_name = Self(name.to_owned());
        display_name.validate()?;
        Ok(display_name)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.0.trim() != self.0 {
            return Err(Error::bad_request(
                "DisplayName must not contain leading or trailing whitespace.",
            ));
        }

        if self.0.len() < NAME_MIN_LENGTH {
            return Err(Error::bad_request(&format!(
                "DisplayName must be at least {NAME_MIN_LENGTH} characters long."
            )));
        }

        if self.0.len() > NAME_MAX_LENGTH {
            return Err(Error::bad_request(&format!(
                "DisplayName must be at most {NAME_MAX_LENGTH} characters long."
            )));
        }

        if self.0 != self.0.trim() {
            return Err(Error::bad_request(
                "DisplayName must not contain leading or trailing whitespace.",
            ));
        }

        Ok(())
    }
}

impl<T> UniqueHandle<T>
where
    T: DBRecord + HasHandle,
{
    /// Create a new handle, ensuring requirements are met.
    /// Use `new_unchecked()` to skip validation.
    pub async fn new(name: &str) -> Result<Self, Error> {
        let handle: UniqueHandle<T> = Self(name.to_owned(), PhantomData);
        handle.validate().await?;
        Ok(handle)
    }

    pub async fn validate(&self) -> Result<(), Error> {
        DisplayName::new(&self.0)?; // Use DisplayName requirements + the following

        if self.0 != self.0.to_lowercase() {
            return Err(Error::bad_request("Handle must be lowercase."));
        }

        if !self.0.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(Error::bad_request(
                "Handle must contain only alphanumeric characters and underscores.",
            ));
        }

        if T::reserved_handles().contains(&self.0.as_str()) {
            return Err(Error::bad_request(&format!(
                "Handle `{}` is reserved.",
                self.0
            )));
        }

        let client = surrealdb_client().await?;

        let field = T::handle_field();
        let existing = T::db_search(&client, field, self.0.to_owned()).await?;

        if !existing.is_empty() {
            return Err(Error::bad_request(&format!(
                "Handle `{}` already exists.",
                self.0
            )));
        }

        Ok(())
    }

    /// Use `new()` to validate
    pub fn new_unchecked(name: String) -> Self {
        Self(name, PhantomData)
    }
}

impl Display for DisplayName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> Display for UniqueHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait HasHandle: DBRecord {
    fn handle_field() -> &'static str;
    fn reserved_handles() -> &'static [&'static str] {
        &[]
    }
}

impl<T: DBRecord> Serialize for UniqueHandle<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, T> Deserialize<'de> for UniqueHandle<T>
where
    T: DBRecord + HasHandle,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HandleVisitor<T>(PhantomData<T>);

        impl<T> serde::de::Visitor<'_> for HandleVisitor<T>
        where
            T: DBRecord + HasHandle,
        {
            type Value = UniqueHandle<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(UniqueHandle::<T>::new_unchecked(value.to_owned()))
            }
        }

        deserializer.deserialize_string(HandleVisitor(PhantomData))
    }
}

/// A phone number in E.164 format
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct PhoneNumber(String);

impl PhoneNumber {
    pub fn new(phone_number: &str) -> Result<Self, Error> {
        let phone_number = Self(phone_number.to_owned());
        phone_number.validate()?;
        Ok(phone_number)
    }

    pub fn validate(&self) -> Result<(), Error> {
        let s = self.0.as_str();

        if !s.starts_with('+') {
            return Err(Error::bad_request(
                "Phone number must start with a '+' (E.164 format)",
            ));
        }

        let digits = &s[1..];

        if digits.len() < 8 || digits.len() > 15 {
            return Err(Error::bad_request(
                "Phone number must be between 8 and 15 digits",
            ));
        }

        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(Error::bad_request("Phone number must be numeric"));
        }

        Ok(())
    }
}

impl Display for PhoneNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An RFC-compliant email address
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn new(email: &str) -> Result<Self, Error> {
        let email = Self(email.to_owned());
        email.validate()?;
        Ok(email)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if !email_address::EmailAddress::is_valid(&self.0) {
            return Err(Error::bad_request("Invalid email address"));
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Sunday,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
}
