use crate::models::user::User;
use crate::{generic::surrealdb_client, models::establishment::Establishment};
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::{
	dbrecord::{DBRecord, SsUuid},
	error::SurrealSocketError,
};

#[derive(Serialize, Deserialize, Default)]
pub struct Staff {
	pub user: SsUuid<User>,
	pub uuid: SsUuid<Staff>,
	pub establishment: SsUuid<Establishment>,
}

#[async_trait]
impl DBRecord for Staff {
	fn table() -> &'static str {
		"staff"
	}

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}

	async fn pre_create_hook(&self) -> Result<(), SurrealSocketError> {
		let client = surrealdb_client().await?;
		let user_uuid = self.user.to_string();
		let establishment_uuid = self.establishment.to_string();

		let query = format!(
			"SELECT * FROM {} WHERE user = $user_uuid AND establishment = $establishment_uuid;",
			Self::table()
		);

		let existing: Vec<Staff> = client
			.query(query)
			.bind(("user_uuid", user_uuid))
			.bind(("establishment_uuid", establishment_uuid))
			.await?
			.take(0)?;

		if !existing.is_empty() {
			return Err(SurrealSocketError::new(
				"User is already a Staff for this establishment.",
			));
		}

		Ok(())
	}
}
