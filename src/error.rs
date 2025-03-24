use rocket::http::Status;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Error {
	status: Status,
	/// Error description for the client
	public_desc: String,
	/// Error description for internal logging.
	///
	/// If none, nothing will be logged.
	internal_desc: Option<String>,
}

impl Error {
	pub fn new(status_code: Status, public_desc: &str, internal_desc: Option<&str>) -> Self {
		Self {
			public_desc: public_desc.to_owned(),
			internal_desc: internal_desc.map(|s| s.to_owned()),
			status: status_code,
		}
	}

	pub fn public_desc(&self) -> String {
		self.public_desc.to_owned()
	}

	pub fn status(&self) -> Status {
		self.status
	}

	/// Create a 500 error with a generic message for the client and a custom message for the server logs.
	pub fn generic_500(log: &str) -> Self {
		Self::new(
			Status::InternalServerError,
			"Internal server error",
			Some(log),
		)
	}

	/// Create a 401 (Unauthorized) error with a generic message for the client.
	pub fn generic_401() -> Self {
		Self::new(Status::Unauthorized, "Invalid credentials", None)
	}

	/// Create a 401 (Unauthorized) error with an "Insufficient permissions" message.
	pub fn insufficient_permissions() -> Self {
		Self::new(Status::Unauthorized, "Insufficient permissions", None)
	}

	/// Create a 404 (Not Found) error with a message specific to a user not being found.
	pub fn user_not_found() -> Self {
		Self::not_found("User not found")
	}

	pub fn forbidden() -> Self {
		Self::new(Status::Forbidden, "Forbidden", None)
	}

	/// Create a 404 (Not Found) error with a specified message for the client.
	pub fn not_found(client_msg: &str) -> Self {
		Self::new(Status::NotFound, client_msg, None)
	}

	/// Create a 422 (Unprocessable Entity) error with a specified message for the client.
	pub fn unprocessable(client_msg: &str) -> Self {
		Self::new(Status::UnprocessableEntity, client_msg, None)
	}

	/// Create an `ErrorResponse` from this `Error`.
	pub fn as_errorresponse(&self) -> ErrorResponse {
		ErrorResponse {
			error: self.public_desc.to_owned(),
		}
	}
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
	/// Error description for the client
	error: String,
}

impl From<Error> for ErrorResponse {
	fn from(e: Error) -> Self {
		e.as_errorresponse()
	}
}

impl From<Error> for rocket::response::status::Custom<rocket::serde::json::Json<ErrorResponse>> {
	/// Converts an `Error` into a `status::Custom<Json<ErrorResponse>>`.
	///
	/// Logs the internal description of the error if it exists, and returns a response
	/// with the public description and the given status.
	fn from(e: Error) -> Self {
		if let Some(internal_desc) = e.internal_desc {
			log::error!("{}", internal_desc);
		}

		rocket::response::status::Custom(
			e.status,
			rocket::serde::json::Json(ErrorResponse {
				error: e.public_desc,
			}),
		)
	}
}

impl From<String> for Error {
	fn from(err: String) -> Self {
		Error::generic_500(&err)
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let desc = if let Some(internal_desc) = &self.internal_desc {
			internal_desc
		} else {
			&self.public_desc
		};
		write!(f, "({}) {}", self.status, desc)
	}
}

impl From<surrealdb::Error> for Error {
	fn from(e: surrealdb::Error) -> Self {
		Error::generic_500(&format!("SurrealDB Operation error: {}", e))
	}
}

impl From<serde_json::error::Error> for Error {
	fn from(e: serde_json::error::Error) -> Self {
		Error::generic_500(&format!("serde_json error: {:?}", e))
	}
}
