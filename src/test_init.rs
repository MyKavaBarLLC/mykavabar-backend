use crate::{
	generic::surrealdb_client,
	models::user::{Role, User},
};
use surreal_socket::dbrecord::DBRecord;

pub async fn test_init() {
	log::info!("Initializing test environment...");
	let client = &surrealdb_client().await.unwrap();
	User::db_delete_table(client).await.unwrap();

	let mut admin = User {
		username: "admin".to_owned(),
		display_name: "Admin".to_owned(),
		roles: vec![Role::Admin],
		..Default::default()
	};

	admin.db_create(client).await.unwrap();
	admin.set_password("admin123").await.unwrap();
	log::info!("Test environment initialized");
}
