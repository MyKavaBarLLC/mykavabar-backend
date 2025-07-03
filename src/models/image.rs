use crate::models::establishment::Establishment;
use crate::models::user::User;
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::{DBRecord, SsUuid};

/// A PNG image
#[derive(Serialize, Deserialize, Default)]
pub struct Image {
    uuid: SsUuid<Image>,
    data: Vec<u8>,
    context: ImageContext,
}

#[derive(Serialize, Deserialize, Default)]
enum ImageContext {
    EstablishmentImage(SsUuid<Establishment>),
    UserAvatar(SsUuid<User>),
    #[default]
    Miscellaneous, // Will probably remain unused - exists for default
}

#[async_trait]
impl DBRecord for Image {
    const TABLE_NAME: &'static str = "images";

    fn uuid(&self) -> SsUuid<Self> {
        self.uuid.to_owned()
    }
}
