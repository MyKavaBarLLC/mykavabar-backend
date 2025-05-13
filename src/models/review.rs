use crate::error::Error;
use crate::models::establishment::Establishment;
use crate::models::user::User;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::{DBRecord, SsUuid};
use utoipa::ToSchema;

const REVIEW_BODY_MAX_LENGTH: usize = 2000;

#[derive(Serialize, Deserialize, Default)]
pub struct Review {
	pub uuid: SsUuid<Review>,
	pub user: SsUuid<User>,
	pub establishment: SsUuid<Establishment>,
	pub rating: ReviewRating,
	pub body: Option<ReviewBody>,
}

impl DBRecord for Review {
	const TABLE_NAME: &'static str = "reviews";

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}
}

/// A 1-5 star rating as an integer
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct ReviewRating(u8);

impl ReviewRating {
	pub fn new(rating: u8) -> Result<Self, Error> {
		let rating = Self(rating);
		rating.validate()?;
		Ok(rating)
	}

	pub fn validate(&self) -> Result<(), Error> {
		if self.0 < 1 || self.0 > 5 {
			return Err(Error::bad_request(
				"Rating must be between 1 and 5 inclusive.",
			));
		}

		Ok(())
	}
}

/// The body of a review. Optional. 2000 characters max.
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct ReviewBody(String);

impl ReviewBody {
	pub fn new(body: String) -> Result<Self, Error> {
		let body = Self(body);
		body.validate()?;
		Ok(body)
	}

	pub fn validate(&self) -> Result<(), Error> {
		if self.0.len() > REVIEW_BODY_MAX_LENGTH {
			return Err(Error::bad_request(&format!(
				"Review body must be {} characters or less.",
				REVIEW_BODY_MAX_LENGTH
			)));
		}

		Ok(())
	}
}
