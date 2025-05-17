use crate::error::Error;
use crate::models::staff_permission::{StaffPermission, StaffPermissionKind};
use crate::models::user::User;
use crate::{generic::surrealdb_client, models::establishment::Establishment};
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::cascade;
use surreal_socket::dbrecord::CascadeDelete;
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
	const TABLE_NAME: &'static str = "staff";

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}

	fn cascade_delete() -> Vec<CascadeDelete> {
		vec![cascade!(StaffPermission, "staff")]
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

impl Staff {
	pub async fn get_permissions(&self) -> Result<Vec<StaffPermissionKind>, Error> {
		let client = surrealdb_client().await?;

		Ok(
			StaffPermission::db_search(&client, "staff", self.uuid.to_string())
				.await?
				.into_iter()
				.map(|p| p.kind)
				.collect::<Vec<StaffPermissionKind>>(),
		)
	}

	pub async fn set_permissions(
		&mut self,
		new_permissions: Vec<StaffPermissionKind>,
	) -> Result<(), Error> {
		let client = surrealdb_client().await?;
		let existing_permissions = StaffPermission::get_belonging_to(&self.uuid).await?;

		for permission in existing_permissions {
			if !new_permissions.contains(&permission.kind) {
				permission.db_delete(&client).await?;
			}
		}

		for permission in new_permissions {
			self.set_permission(permission).await?;
		}

		Ok(())
	}

	pub async fn set_permission(&mut self, permission: StaffPermissionKind) -> Result<(), Error> {
		let client = surrealdb_client().await?;
		let existing_permissions = StaffPermission::get_belonging_to(&self.uuid).await?;

		if !existing_permissions.iter().any(|p| p.kind == permission) {
			StaffPermission::new(&self.uuid, permission)
				.db_create(&client)
				.await?;
		}

		Ok(())
	}

	pub async fn get_user(&self) -> Result<User, Error> {
		let client = surrealdb_client().await?;

		match User::db_by_id(&client, &self.user.uuid_string()).await? {
			Some(user) => Ok(user),
			None => {
				self.db_delete(&client).await?;
				Err(Error::generic_500(&format!(
					"Illegal state: User not found for staff {}. Staff deleted.",
					self.uuid
				)))
			}
		}
	}

	pub async fn has_permission(&self, permission: StaffPermissionKind) -> Result<bool, Error> {
		let permissions = self.get_permissions().await?;
		Ok(permissions.contains(&permission))
	}
}
