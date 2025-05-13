use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::{DBRecord, SsUuid};

#[derive(Serialize, Deserialize, Default)]
pub struct Image {
	uuid: SsUuid<Image>,
}

#[async_trait]
impl DBRecord for Image {
	const TABLE_NAME: &'static str = "images";

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}
}
