use crate::models::staff::Staff;
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::{DBRecord, SsUuid};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize)]
pub struct StaffPermission {
	pub uuid: SsUuid<StaffPermission>,
	pub staff: SsUuid<Staff>,
	pub kind: StaffPermissionKind,
}

#[async_trait]
impl DBRecord for StaffPermission {
	const TABLE_NAME: &'static str = "staff_permissions";

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}
}

#[derive(Serialize, Deserialize, ToSchema, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StaffPermissionKind {
	Admin,
}
