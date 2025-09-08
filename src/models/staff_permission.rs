use crate::{error::Error, generic::surrealdb_client, models::staff::Staff};
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

#[derive(Serialize, Deserialize, ToSchema, PartialEq, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StaffPermissionKind {
    Admin,
}

impl StaffPermission {
    pub fn new(staff: &SsUuid<Staff>, kind: StaffPermissionKind) -> Self {
        Self {
            uuid: SsUuid::new(),
            staff: staff.clone(),
            kind,
        }
    }

    pub async fn get_belonging_to(staff: &SsUuid<Staff>) -> Result<Vec<StaffPermission>, Error> {
        let client = surrealdb_client().await.unwrap();
        
        let permissions =
            StaffPermission::db_search(&client, "staff", staff.to_uuid_string()).await?;

        Ok(permissions)
    }
}
