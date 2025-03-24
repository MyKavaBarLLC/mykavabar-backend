use crate::{
	error::Error,
	generic::{surrealdb_client, UUID},
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};
use std::{
	any::Any,
	collections::HashMap,
	fmt::{Display, Formatter},
};
use surrealdb::sql::Thing;

/// Methods associated with SurrealDB tables
///
/// This trait should be implemented for concrete types.
/// For generic types, use the `GenericResource` struct instead.
#[async_trait]
pub trait DBRecord: Any + Serialize + DeserializeOwned + Send + Sync {
	/// Get the associated table name
	fn table() -> &'static str;

	/// Get the UUID associated with the record
	fn uuid(&self) -> UUID<Self>;

	/// Get the Thing (`surrealdb::sql::thing::Thing`) associated with the record
	fn thing(&self) -> Thing {
		self.uuid().thing()
	}

	/// Whether records should be moved to a table named `z_trashed_{table}` on `db_delete()`
	fn use_trash() -> bool {
		false
	}

	/// This method is called immediately before a record is deleted by `db_delete()`.
	///
	/// Override this method to perform checks or cleanup tasks before the object's deletion.
	///
	/// If the method returns an `Error`, the deletion will be aborted and `db_delete()` will return the error.
	async fn delete_hook(&self) -> Result<(), Error> {
		Ok(())
	}

	/// Get an object from SurrealDB by its ID, or `None` if not found.
	///
	/// Returns an `Error` if SurrealDB unexpectedly fails.
	async fn db_by_id(id: &str) -> Result<Option<Self>, Error> {
		let thing = Thing::from((Self::table().to_owned(), id.to_owned()));
		let uuid: UUID<Self> = UUID::from(thing);
		let item: Option<Self> = Self::db_search_one("uuid", uuid).await?;
		Ok(item.into_iter().next())
	}

	/// Get a `Vec` of objects in the database where `field` matches `value`.
	///
	/// Returns an `Error` if SurrealDB unexpectedly fails.
	///
	/// If only one record at most is expected, use search_one() for an `Option` instead of a `Vec`.
	async fn db_search<T: Serialize + Clone + Send + 'static>(
		field: &str,
		value: T,
	) -> Result<Vec<Self>, Error> {
		Self::db_query(SQLCommand::Select, field.to_string(), '=', value).await
	}

	async fn db_query<T: Serialize + Clone + Send + 'static>(
		sql_command: SQLCommand,
		field: String,
		operand: char,
		value: T,
	) -> Result<Vec<Self>, Error> {
		let db = surrealdb_client().await?;
		db.set("table", Self::table()).await?;
		db.set("value", value).await?;

		// Update when this issue is resolved:
		// https://github.com/surrealdb/surrealdb/issues/1693
		let query = format!(
			"{} FROM type::table($table) WHERE {} {} $value",
			sql_command, field, operand
		);

		let mut response = db.query(query).await?;
		let result: Vec<Self> = response.take(0)?;
		Ok(result)
	}

	/// Get a single object in the database where `field` matches `value`, or `None` if not found.
	///
	/// Returns an `Error` if SurrealDB unexpectedly fails.
	///
	/// If searching by `id`, use `from_id()` instead.
	async fn db_search_one<T: Serialize + Clone + Send + 'static>(
		field: &str,
		value: T,
	) -> Result<Option<Self>, Error> {
		Ok(Self::db_search(field, value).await?.into_iter().next())
	}

	/// Add a new record to the database and return it.
	async fn db_create(&self) -> Result<Self, Error> {
		let db = surrealdb_client().await?;
		let serde_value = serde_json::to_value(self)?;
		let id = self.uuid().uuid_string();

		let opt: Option<Self> = db
			.create((Self::table(), id.to_owned()))
			.content(serde_value)
			.await?;

		match opt {
			Some(e) => Ok(e),
			None => Err(Error::generic_500("Failed to create record")),
		}
	}

	/// Delete a record from the database.
	async fn db_delete(&self) -> Result<(), Error> {
		let db = surrealdb_client().await?;
		self.delete_hook().await?;

		if Self::use_trash() {
			let created: Option<Self> = db
				.create((
					format!("z_trashed_{}", Self::table()),
					self.uuid().uuid_string(),
				))
				.content(serde_json::to_value(self)?)
				.await?;

			created.ok_or_else(|| {
				Error::generic_500(&format!(
					"Failed to create trash table record: {}",
					self.uuid().uuid_string()
				))
			})?;
		}

		let thing = self.thing();
		let _: Option<Self> = db.delete((thing.tb, self.uuid().uuid_string())).await?;
		Ok(())
	}

	/// Update a single field of a record in the database.
	///
	/// Use `db_update_fields()` to update multiple fields at once.
	async fn db_update_field<T: Serialize + Sync>(
		&self,
		field: &str,
		value: &T,
	) -> Result<(), Error> {
		self.db_update_fields(vec![(field, value)]).await?;
		Ok(())
	}

	/// Update several fields of a record in the database at once.
	///
	/// The first value of the tuple is the field name, and the second is the value to set.
	async fn db_update_fields<T: Serialize + Sync + Send + Clone>(
		&self,
		updates: Vec<(&str, T)>,
	) -> Result<(), Error> {
		let mut merge_data = HashMap::<String, serde_json::Value>::new();
		merge_data.insert("updated_at".to_owned(), serde_json::to_value(Utc::now())?);

		for update in updates {
			merge_data.insert(update.0.to_owned(), serde_json::to_value(update.1.clone())?);
		}

		let db = surrealdb_client().await?;

		let _: Option<Self> = db
			.update((Self::table(), self.uuid().uuid_string()))
			.merge(merge_data)
			.await?;

		Ok(())
	}

	async fn db_all() -> Result<Vec<Self>, Error> {
		let db = surrealdb_client().await?;
		let table = Self::table();
		db.set("table", table).await?;
		let mut response = db.query("SELECT * FROM type::table($table)").await?;
		let result: surrealdb::Value = response.take(0)?;
		let serde_value = result.into_inner().into_json();
		let value: Vec<Self> = serde_json::from_value(serde_value).unwrap();
		Ok(value)
	}

	/// For each record in the table, add any missing properties with default values to the record in the database.
	///
	/// Record retrieval already uses default values for missing fields, but this exists just in case it's ever needed.
	#[allow(unused)]
	async fn db_refresh_table() -> Result<(), Error> {
		let result = Self::db_all().await?;
		let db = surrealdb_client().await?;
		let table = Self::table();

		for item in result {
			let _: Option<Self> = db
				.update((table, item.uuid().uuid_string()))
				.content(item)
				.await?;
		}

		log::info!("Table refreshed: {}", table);
		Ok(())
	}

	async fn db_delete_table() -> Result<(), Error> {
		let db = surrealdb_client().await?;
		let table = Self::table();
		db.set("table", table).await?;
		db.query(format!("REMOVE TABLE {}", table)).await?;
		Ok(())
	}
}

pub enum SQLCommand {
	Select,
	Delete,
}

impl Display for SQLCommand {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			SQLCommand::Select => write!(f, "SELECT *"),
			SQLCommand::Delete => write!(f, "DELETE"),
		}
	}
}
