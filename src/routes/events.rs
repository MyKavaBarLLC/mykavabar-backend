use crate::error::Error;
use crate::generic::surrealdb_client;
use crate::generic::GenericResponse;
use crate::models::event::Event;
use crate::models::event::EventResponse;
use rocket::response::status;
use rocket::serde::json::Json;
use surreal_socket::dbrecord::DBRecord;

/// Get Upcoming Events
#[utoipa::path(
    get,
    path = "/v1/events/upcoming",
    responses(
        (status = 200, description = "List of upcoming events", body = [EventResponse]),
    ),
    security(),
    tag = "event"
)]
#[rocket::get("/v1/events/upcoming")]
pub async fn get_upcoming_events(
) -> Result<Json<Vec<EventResponse>>, status::Custom<Json<GenericResponse>>> {
    let client = surrealdb_client().await.map_err(Error::from)?;
    let all_events = Event::db_all(&client).await.map_err(Error::from)?;
    // todo: upcoming only - probably add a next_occurrence field and job to update it
    let response: Vec<EventResponse> = all_events.into_iter().map(EventResponse::from).collect();
    Ok(Json(response))
}
