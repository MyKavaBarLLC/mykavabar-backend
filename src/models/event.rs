use crate::generic::Weekday;
use crate::models::establishment::{Establishment, TimePeriod};
use crate::models::user::User;
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::{DBRecord, SsUuid};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize)]
pub struct Event {
    pub uuid: SsUuid<Event>,
    pub host: SsUuid<Establishment>,
    pub title: String,
    pub description: Option<String>,
    pub attendees: Vec<SsUuid<User>>,
    pub schedule: EventSchedule,
}

#[async_trait]
impl DBRecord for Event {
    const TABLE_NAME: &'static str = "events";

    fn uuid(&self) -> SsUuid<Self> {
        self.uuid.to_owned()
    }
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub enum EventSchedule {
    Once {
        date: chrono::NaiveDate,
        period: TimePeriod,
    },
    Recurring {
        weekdays: Vec<Weekday>,
        period: TimePeriod,
    },
}

/// Event Response
#[derive(Serialize, ToSchema)]
pub struct EventResponse {
    pub uuid: String,
    /// Establishment UUID
    pub host: String,
    pub title: String,
    pub description: Option<String>,
    pub attendee_count: usize,
    pub schedule: EventSchedule,
}

impl From<Event> for EventResponse {
    fn from(event: Event) -> Self {
        Self {
            uuid: event.uuid.to_uuid_string(),
            host: event.host.to_uuid_string(),
            title: event.title,
            description: event.description,
            attendee_count: event.attendees.len(),
            schedule: event.schedule,
        }
    }
}
