use crate::models::establishment::TimePeriod;
use chrono::NaiveDate;
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::dbrecord::Expirable;
use surreal_socket::dbrecord::{DBRecord, SsUuid};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct StaffScheduleEntry {
    pub uuid: SsUuid<StaffScheduleEntry>,
    pub shifts: Vec<TimePeriod>,
    pub date: NaiveDate,
}

#[async_trait]
impl DBRecord for StaffScheduleEntry {
    const TABLE_NAME: &'static str = "staff_schedule_entry";

    fn uuid(&self) -> SsUuid<Self> {
        self.uuid.to_owned()
    }
}

impl Expirable for StaffScheduleEntry {
    fn start_time_field() -> &'static str {
        "date"
    }

    fn expiry_seconds() -> u64 {
        // Arbitrarily 1 week
        60 * 60 * 24 * 7
    }
}

impl StaffScheduleEntry {
    /// Creates a new `StaffScheduleEntry` for the given date without persisting it to the database.
    pub fn new(date: NaiveDate) -> Self {
        Self {
            uuid: SsUuid::new(),
            shifts: Vec::new(),
            date,
        }
    }

    pub fn conflicts_with_period(&self, period: &TimePeriod) -> bool {
        self.shifts
            .iter()
            .any(|shift| shift.start() < period.end() && shift.end() > period.start())
    }

    pub fn add_shift(&mut self, period: TimePeriod) -> Result<(), String> {
        if self.conflicts_with_period(&period) {
            return Err("Shift conflicts with existing shifts".to_string());
        }

        let pos = self
            .shifts
            .binary_search_by_key(&period.start(), |p| p.start());

        match pos {
            Ok(_) => Err("Shift already exists".to_string()),
            Err(index) => {
                self.shifts.insert(index, period);
                Ok(())
            }
        }
    }
}
