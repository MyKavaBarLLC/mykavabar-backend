use crate::models::establishment::Establishment;
use crate::models::user::User;
use crate::{error::Error, generic::surrealdb_client};
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::{DBRecord, SsUuid};
use surreal_socket::error::SurrealSocketError;
use utoipa::ToSchema;

const REVIEW_BODY_MAX_LENGTH: usize = 2000;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Review {
    pub uuid: SsUuid<Review>,
    pub user: SsUuid<User>,
    pub context: ReviewContext,
    pub rating: ReviewRating,
    pub body: Option<ReviewBody>,
}

#[async_trait]
impl DBRecord for Review {
    const TABLE_NAME: &'static str = "reviews";

    fn uuid(&self) -> SsUuid<Self> {
        self.uuid.to_owned()
    }

    async fn post_update_hook(&self) -> Result<(), SurrealSocketError> {
        let self_clone = self.clone();

        tokio::spawn(async move {
            if let Err(e) = Establishment::on_review_update(&self_clone).await {
                log::error!("Establishment::on_review_update error: {}", e);
            }
        });

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub enum ReviewContext {
    EstablishmentReview(SsUuid<Establishment>),
    #[default]
    Miscellaneous, // Will probably remain unused - exists for default
}

impl Review {
    pub fn new(
        user: &SsUuid<User>,
        context: ReviewContext,
        rating: ReviewRating,
        body: Option<ReviewBody>,
    ) -> Self {
        Self {
            uuid: SsUuid::new(),
            user: user.to_owned(),
            rating,
            body,
            context,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.rating.validate()?;

        if let Some(ref body) = self.body {
            body.validate()?;
        }

        Ok(())
    }

    pub async fn get_user(&self) -> Result<User, Error> {
        let client = surrealdb_client().await?;

        match User::db_by_id(&client, &self.user.uuid_string()).await? {
            Some(user) => Ok(user),
            None => Err(Error::not_found("User not found.")),
        }
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

    pub fn value(&self) -> u8 {
        self.0
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
