use crate::{
	dbrecord::DBRecord,
	models::user::{Role, User},
};

pub async fn test_init() {
	log::info!("Initializing test environment");
	User::db_delete_table().await.unwrap();

	let mut admin = User {
		username: "admin".to_owned(),
		display_name: "Admin".to_owned(),
		roles: vec![Role::Admin],
		..Default::default()
	};

	admin.db_create().await.unwrap();
	admin.set_password("admin123").await.unwrap();
}
