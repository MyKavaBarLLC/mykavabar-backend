use crate::generic::DisplayName;
use crate::generic::GenericResponse;
use crate::generic::UniqueHandle;
use crate::models::establishment::Coordinate;
use crate::models::establishment::Establishment;
use crate::models::establishment::Rating;
use crate::models::establishment::Schedule;
use crate::routes::openapi::HandleDummy;
use crate::{
	error::Error,
	generic::{surrealdb_client, BearerToken},
};
use core::str;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use serde::Deserialize;
use strum::AsRefStr;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

/// Establishment Card - Minimal establishment info for search results
#[derive(Serialize, ToSchema)]
pub struct EstablishmentCard {
	uuid: String,
	display_name: DisplayName,
	/// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
	#[schema(value_type = String)]
	handle: UniqueHandle<HandleDummy>,
	rating: Rating,
}

impl From<Establishment> for EstablishmentCard {
	fn from(establishment: Establishment) -> Self {
		Self {
			uuid: establishment.uuid.uuid_string(),
			display_name: establishment.display_name,
			handle: UniqueHandle::new_unchecked(establishment.handle.to_string()),
			rating: establishment.rating,
		}
	}
}

/// Establishment Request
#[derive(Deserialize, ToSchema)]
pub struct EstablishmentRequest {
	pub display_name: Option<DisplayName>,
	/// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
	#[schema(value_type = String)]
	pub handle: Option<UniqueHandle<HandleDummy>>,
	pub schedule: Option<Schedule>,
	pub coordinate: Option<Coordinate>,
	pub rating: Option<Rating>,
}

/// Establishment Response
#[derive(Serialize, ToSchema)]
pub struct EstablishmentResponse {
	pub display_name: DisplayName,
	/// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
	#[schema(value_type = String)]
	pub handle: UniqueHandle<HandleDummy>,
	pub schedule: Schedule,
	pub coordinate: Coordinate,
	pub rating: Rating,
}

impl From<Establishment> for EstablishmentResponse {
	fn from(establishment: Establishment) -> Self {
		Self {
			display_name: establishment.display_name,
			handle: UniqueHandle::new_unchecked(establishment.handle.to_string()),
			schedule: establishment.schedule,
			rating: establishment.rating,
			coordinate: establishment.coordinate,
		}
	}
}

/// Create establishment
#[utoipa::path(
    post,
    path = "/v1/establishments",
    description = "Create an Establishment. Admins only.",
	request_body(content = EstablishmentRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Fetched establishment", body = EstablishmentResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::post("/v1/establishments", data = "<request>")]
pub async fn create_establishment(
	request: Json<EstablishmentRequest>,
	bearer_token: BearerToken,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
	let user = bearer_token.validate().await?.user().await?;

	if !user.is_admin {
		return Err(Error::forbidden().into());
	}

	let new_establishment = Establishment::try_from_request(request.0).await?;
	let client = surrealdb_client().await.map_err(Into::<Error>::into)?;

	new_establishment
		.db_create(&client)
		.await
		.map_err(Into::<Error>::into)?;

	Ok(Json(new_establishment.into()))
}

/// Get establishment
#[utoipa::path(
    get,
    path = "/v1/establishments/{id_or_handle}",
    description = "Get a single Establishment by either ID or handle",
	params(
        ("id_or_handle" = String, Path, description = "Establishment ID or handle")
    ),
    responses(
        (status = 200, description = "Establishment fetched", body = EstablishmentResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
	security(),
    tag = "establishment"
)]
#[rocket::get("/v1/establishments/<id_or_handle>")]
pub async fn get_establishment(
	id_or_handle: String,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
	match Establishment::by_id_or_handle(&id_or_handle).await? {
		Some(establishment) => Ok(Json(establishment.into())),
		None => Err(Error::not_found("Establishment not found").into()),
	}
}

/// Update establishment
#[utoipa::path(
	patch,
	path = "/v1/establishments/{id}",
	params(
        ("id" = String, Path, description = "Establishment ID")
    ),
	description = "Update an Establishment if the User is a Staff with sufficient permissions (or is an admin)",
	request_body(content = EstablishmentRequest, content_type = "application/json"),
	responses(
		(status = 200, description = "Updated establishment", body = EstablishmentResponse),
		(status = 401, description = "Unauthorized", body = GenericResponse),
		(status = 403, description = "Forbidden", body = GenericResponse)
	),
	security(
        ("bearerAuth" = [])
    ),
	tag = "establishment"
)]
#[rocket::patch("/v1/establishments/<id>", data = "<request>")]
pub async fn update_establishment(
	request: Json<EstablishmentRequest>,
	id: String,
	bearer_token: BearerToken,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
	let user = bearer_token.validate().await?.user().await?;

	if !user.is_admin {
		// todo: Staff perms
		return Err(Error::forbidden().into());
	}

	let client = surrealdb_client().await.map_err(Into::<Error>::into)?;

	let mut establishment = match Establishment::db_by_id(&client, &id)
		.await
		.map_err(Into::<Error>::into)?
	{
		Some(establishment) => establishment,
		None => return Err(Error::not_found("Establishment not found").into()),
	};

	if let Some(display_name) = &request.display_name {
		display_name.validate()?;
		establishment.display_name = display_name.clone();
	}

	if let Some(handle) = &request.handle {
		establishment.handle = UniqueHandle::new(&handle.to_string()).await?;
	}

	if let Some(schedule) = &request.schedule {
		schedule.validate()?;
		establishment.schedule = schedule.clone();
	}

	if let Some(coordinate) = &request.coordinate {
		establishment.coordinate = coordinate.clone();
	}

	if let Some(rating) = &request.rating {
		rating.validate()?;
		establishment.rating = rating.clone();
	}

	establishment
		.db_overwrite(&client)
		.await
		.map_err(Into::<Error>::into)?;

	Ok(Json(establishment.into()))
}

/// Search establishments
#[utoipa::path(
	post,
	path = "/v1/establishments/search",
	description = "Returns Establishment cards with minimal info. Use `GET /v1/establishments/<id_or_handle>` to get full details.",
	request_body(content = EstablishmentSearchRequest, content_type = "application/json"),
	responses(
		(status = 200, description = "List of establishment cards", body = [EstablishmentCard]),
		(status = 401, description = "Unauthorized", body = GenericResponse),
		(status = 403, description = "Forbidden", body = GenericResponse)
	),
	security(),
	tag = "establishment"
)]
#[rocket::post("/v1/establishments/search", data = "<request>")]
pub async fn search_establishments_route(
	request: Json<EstablishmentSearchRequest>,
) -> Result<Json<Vec<EstablishmentCard>>, status::Custom<Json<GenericResponse>>> {
	let establishments = search_establishments(request.0).await?;

	let establishment_cards: Vec<EstablishmentCard> = establishments
		.into_iter()
		.map(EstablishmentCard::from)
		.collect();

	Ok(Json(establishment_cards))
}

async fn search_establishments(
	search: EstablishmentSearchRequest,
) -> Result<Vec<Establishment>, Error> {
	let client = surrealdb_client().await?;

	if let Some(name) = search.name {
		// todo: better
		let query = format!("SELECT * FROM {} WHERE display_name = $name OR display_name CONTAINS $name ORDER BY display_name;", Establishment::table());
		let establishments: Vec<Establishment> =
			client.query(query).bind(("name", name)).await?.take(0)?;

		return Ok(establishments);
	}

	let query = if let Some(loc) = search.location {
		let max_distance = search.radius.unwrap_or(1000.0) * 1000.0; // Convert to meters
		format!(
			r#"
				SELECT *,
					geo::distance(surreal_geo_point, {{
						type: "Point",
						coordinates: [{}, {}]
					}}) AS distance
				FROM establishment
				WHERE geo::distance(surreal_geo_point, {{
						type: "Point",
						coordinates: [{}, {}]
					}}) < {}
				ORDER BY {} DESC
				LIMIT 100;
			"#,
			loc.lng,
			loc.lat,
			loc.lng,
			loc.lat,
			max_distance,
			search.sort_by.as_ref()
		)
	} else {
		if search.sort_by == SortField::Distance {
			return Err(Error::bad_request("Distance sort requires a location"));
		}

		format!(
			"SELECT * FROM {} ORDER BY {} DESC LIMIT 10;",
			Establishment::table(),
			search.sort_by.as_ref()
		)
	};

	let establishments: Vec<Establishment> = client.query(&query).await?.take(0)?;
	Ok(establishments)
}

/// Establishment Search Request
#[derive(Deserialize, ToSchema)]
pub struct EstablishmentSearchRequest {
	pub location: Option<Coordinate>,

	/// In kilometers. Only applicable if location is provided. Defaults to 1000.
	#[schema(example = 300)]
	pub radius: Option<f32>,

	pub sort_by: SortField,

	/// Search by name. If set, all other filters are ignored.
	#[schema(example = json!(null))]
	pub name: Option<String>,
}

#[derive(Deserialize, Serialize, ToSchema, AsRefStr, PartialEq)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SortField {
	Distance,
	Rating,
}

// todo: delete route
