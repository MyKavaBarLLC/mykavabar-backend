use crate::generic::{DisplayName, HasHandle, UniqueHandle};
use crate::models::staff::Staff;
use crate::routes::establishment::EstablishmentRequest;
use crate::{error::Error, generic::surrealdb_client};
use rocket::async_trait;
use rocket::serde::Deserialize;
use rocket::serde::Serialize;
use std::fmt::{Display, Formatter};
use surreal_socket::{
	cascade,
	dbrecord::{CascadeDelete, DBRecord, SsUuid},
	error::SurrealSocketError,
};
use utoipa::ToSchema;

const MINUTES_IN_DAY: u16 = 1440;

#[derive(Serialize, Deserialize, Default)]
pub struct Establishment {
	pub uuid: SsUuid<Establishment>,
	pub display_name: DisplayName,
	pub handle: UniqueHandle<Establishment>,
	pub schedule: Schedule,
	pub coordinate: Coordinate,
	pub rating: Rating,
}

impl HasHandle for Establishment {
	fn handle_field() -> &'static str {
		"handle"
	}

	fn reserved_handles() -> &'static [&'static str] {
		&["search"]
	}
}

#[async_trait]
impl DBRecord for Establishment {
	const TABLE_NAME: &'static str = "establishment";

	fn uuid(&self) -> SsUuid<Self> {
		self.uuid.to_owned()
	}

	async fn post_update_hook(&self) -> Result<(), SurrealSocketError> {
		let client = surrealdb_client().await?;

		let query = format!(
			r#"
			UPDATE {} SET surreal_geo_point = {{
				type: "Point",
				coordinates: [{}, {}]
			}} WHERE uuid = {};
			"#,
			Self::table(),
			self.coordinate.lng,
			self.coordinate.lat,
			serde_json::to_string(&self.uuid())?
		);

		client.query(&query).await?;
		Ok(())
	}

	fn use_trash() -> bool {
		true
	}

	fn cascade_delete() -> Vec<CascadeDelete> {
		vec![cascade!(Staff, "establishment")]
	}
}

impl Establishment {
	pub async fn by_id_or_handle(id_or_handle: &str) -> Result<Option<Self>, Error> {
		let client = surrealdb_client().await?;

		Ok(if id_or_handle.contains('-') {
			Self::db_search_one(
				&client,
				"uuid",
				format!("{}:{}", Self::table(), &id_or_handle),
			)
			.await?
		} else {
			Self::db_search_one(&client, Self::handle_field(), id_or_handle.to_owned()).await?
		})
	}

	pub async fn try_from_request(request: EstablishmentRequest) -> Result<Self, Error> {
		let establishment = Self {
			uuid: SsUuid::<Establishment>::new(),
			display_name: request
				.display_name
				.ok_or(Error::bad_request("Display name is required"))?,
			handle: if let Some(handle) = request.handle {
				UniqueHandle::new(&handle.to_string()).await?
			} else {
				return Err(Error::bad_request("Handle is required"));
			},
			schedule: request.schedule.unwrap_or_default(),
			coordinate: request.coordinate.unwrap_or_default(),
			rating: request.rating.unwrap_or_default(),
		};

		Ok(establishment)
	}
}

/// A schedule. Periods must be chronological and non-overlapping
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct Schedule {
	pub sun: Vec<TimePeriod>,
	pub mon: Vec<TimePeriod>,
	pub tue: Vec<TimePeriod>,
	pub wed: Vec<TimePeriod>,
	pub thu: Vec<TimePeriod>,
	pub fri: Vec<TimePeriod>,
	pub sat: Vec<TimePeriod>,
}

impl Schedule {
	pub fn validate(&self) -> Result<(), Error> {
		let days = [
			&self.sun, &self.mon, &self.tue, &self.wed, &self.thu, &self.fri, &self.sat,
		];

		let mut minute = 0;

		for day in days {
			for period in day {
				period.validate()?;

				if period.begin < minute {
					return Err(Error::bad_request(
						"Time periods must be in ascending order and non-overlapping",
					));
				}

				minute = period.end;
			}
		}

		Ok(())
	}
}

/// A time period in minutes since midnight.
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct TimePeriod {
	/// 0 to 1439. Must be less than `end`.
	#[schema(maximum = 1439)]
	begin: u16,
	/// Can be over 1440 if the period extends until after midnight.
	#[schema(maximum = 2879)]
	end: u16,
}

impl TimePeriod {
	pub fn new(begin: u16, end: u16) -> Result<Self, Error> {
		let period = Self { begin, end };
		period.validate()?;
		Ok(period)
	}

	pub fn validate(&self) -> Result<(), Error> {
		if self.begin >= MINUTES_IN_DAY || self.end >= MINUTES_IN_DAY * 2 || self.begin > self.end {
			return Err(Error::bad_request("Invalid time period"));
		}

		Ok(())
	}
}

/// Geographic coordinate
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct Coordinate {
	/// Longitude in decimal degrees, negative for west
	#[schema(maximum = 180.0, minimum = -180.0, example = -80.1434)]
	pub lng: f64,
	/// Latitude in decimal degrees, negative for south
	#[schema(maximum = 90.0, minimum = -90.0, example = 26.1223)]
	pub lat: f64,
}

impl Display for Coordinate {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "[{}, {}]", self.lat, self.lng)
	}
}

impl Coordinate {
	pub fn new(lat: f64, lng: f64) -> Result<Self, Error> {
		let coordinate = Self { lat, lng };
		coordinate.validate()?;
		Ok(coordinate)
	}

	pub fn validate(&self) -> Result<(), Error> {
		if self.lat < -90.0 || self.lat > 90.0 || self.lng < -180.0 || self.lng > 180.0 {
			return Err(Error::bad_request("Coordinate out of bounds"));
		}

		Ok(())
	}
}

/// A 1-5 star rating, represented as a u16 in hundredths. (100-500)
///
/// A rating of 0 is considered unrated. 1-99 is invalid.
#[derive(Serialize, Deserialize, ToSchema, Default, Clone)]
pub struct Rating(u16);

impl Rating {
	pub fn new(rating: u16) -> Result<Self, Error> {
		let rating = Self(rating);
		rating.validate()?;
		Ok(rating)
	}

	pub fn validate(&self) -> Result<(), Error> {
		// Allow 0 (unrated) and 100-500
		if (1..100).contains(&self.0) || self.0 > 500 {
			return Err(Error::bad_request("Rating out of bounds"));
		}

		Ok(())
	}
}
