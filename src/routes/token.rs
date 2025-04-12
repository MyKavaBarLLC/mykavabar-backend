use crate::{
	error::{Error, ErrorResponse},
	generic::surrealdb_client,
	models::{
		session::{Session, ACCESS_TOKEN_EXPIRY_SECONDS, REFRESH_TOKEN_EXPIRY_SECONDS},
		user::User,
	},
};
use rocket::{
	form::{Form, FromForm},
	http::Status,
	post,
	response::status,
	serde::json::Json,
};
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::DBRecord;

#[post(
	"/v1/auth/token",
	data = "<token_request>",
	format = "application/x-www-form-urlencoded"
)]
/// Request tokens
///
/// [OAuth2 Token Endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2)
pub async fn token_form(
	token_request: Form<TokenRequest>,
) -> Result<Json<TokenResponse>, status::Custom<Json<ErrorResponse>>> {
	token(token_request.into_inner()).await
}

#[post(
	"/v1/auth/token",
	data = "<token_request>",
	format = "application/json"
)]
pub async fn token_json(
	token_request: Json<TokenRequest>,
) -> Result<Json<TokenResponse>, status::Custom<Json<ErrorResponse>>> {
	token(token_request.into_inner()).await
}

/// Requests from both json and form content types for /auth/token are handled by this function
pub async fn token(
	token_request: TokenRequest,
) -> Result<Json<TokenResponse>, status::Custom<Json<ErrorResponse>>> {
	let client = surrealdb_client().await.map_err(Into::<Error>::into)?;

	let user = User::db_search_one(&client, "username", token_request.username.clone())
		.await
		.map_err(Into::<Error>::into)?
		.ok_or(Error::generic_401())?;

	let mut session = match token_request.grant_type.as_str() {
		"password" => {
			let password = token_request.password.ok_or(Error::new(
				Status::BadRequest,
				"Missing password",
				None,
			))?;

			user.verify_password(&password)?;
			let session = Session::new(&user.uuid())?;

			session
				.db_create(&client)
				.await
				.map_err(Into::<Error>::into)?;

			session
		}
		"refresh_token" => {
			let refresh_token = token_request.refresh_token.ok_or(Error::new(
				Status::BadRequest,
				"Missing refresh token",
				None,
			))?;

			user.get_session_from_refresh_token(&refresh_token)
				.await?
				.ok_or(Error::generic_401())?
		}
		_ => return Err(Error::new(Status::BadRequest, "Invalid grant type", None).into()),
	};

	let response = TokenResponse::generate(&mut session).await?;
	Ok(Json(response))
}

#[derive(Serialize)]
/// [Successful Response](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)
pub struct TokenResponse {
	/// Used for Bearer authentication by including it in the Authorization header as Bearer <access_token>.
	access_token: String,
	/// Used to obtain new access tokens with the refresh_token grant type in the same authorization process.
	refresh_token: String,
	/// The lifetime in seconds of the access token.
	expires_in: u64,
	/// "Bearer"
	token_type: String,
	/// The lifetime in seconds of the refresh token.
	x_refresh_token_expires_in: u64,
}

impl TokenResponse {
	pub async fn generate(session: &mut Session) -> Result<Self, Error> {
		let refresh_token = session.rotate_refresh_token().await?;
		let access_token = session.generate_access_token()?;

		Ok(Self {
			access_token,
			refresh_token,
			..Default::default()
		})
	}
}

impl Default for TokenResponse {
	fn default() -> Self {
		Self {
			access_token: "".to_string(),
			refresh_token: "".to_string(),
			expires_in: ACCESS_TOKEN_EXPIRY_SECONDS,
			token_type: "Bearer".to_string(),
			x_refresh_token_expires_in: REFRESH_TOKEN_EXPIRY_SECONDS,
		}
	}
}

#[derive(Debug, FromForm, Serialize, Deserialize)]
/// [Access Token Request](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2)
pub struct TokenRequest {
	/// "password" or "refresh_token"
	grant_type: String,
	/// User.username
	username: String,
	/// Required when grant_type is "password"
	password: Option<String>,
	/// Required when grant_type is "refresh_token"
	///
	/// When provided, the refresh token is invalidated and a new one is generated with the new access token.
	refresh_token: Option<String>,
}

impl TokenRequest {
	/// Create a TokenRequest using the `password grant` type
	pub fn new_password_grant(username: &str, password: &str) -> Self {
		Self {
			grant_type: "password".to_string(),
			username: username.to_owned(),
			password: Some(password.to_owned()),
			refresh_token: None,
		}
	}
}
