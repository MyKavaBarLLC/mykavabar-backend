use crate::error::Error;
use crate::models::establishment::{TimePeriod, MINUTES_IN_DAY};
use crate::models::staff_permission::{StaffPermission, StaffPermissionKind};
use crate::models::staff_schedule_entry::StaffScheduleEntry;
use crate::models::user::User;
use crate::{generic::surrealdb_client, models::establishment::Establishment};
use chrono::NaiveDate;
use chrono::Timelike;
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use surreal_socket::cascade;
use surreal_socket::dbrecord::CascadeDelete;
use surreal_socket::{
    dbrecord::{DBRecord, SsUuid},
    error::SurrealSocketError,
};

#[derive(Serialize, Deserialize, Default)]
pub struct Staff {
    pub uuid: SsUuid<Staff>,
    pub user: SsUuid<User>,
    pub establishment: SsUuid<Establishment>,
}

#[async_trait]
impl DBRecord for Staff {
    const TABLE_NAME: &'static str = "staff";

    fn uuid(&self) -> SsUuid<Self> {
        self.uuid.to_owned()
    }

    fn cascade_delete() -> Vec<CascadeDelete> {
        vec![cascade!(StaffPermission, "staff")]
    }

    async fn pre_create_hook(&self) -> Result<(), SurrealSocketError> {
        let client = surrealdb_client().await?;
        let user_uuid = self.user.to_string();
        let establishment_uuid = self.establishment.to_string();

        let query = format!(
            "SELECT * FROM {} WHERE user = $user_uuid AND establishment = $establishment_uuid;",
            Self::table()
        );

        let existing: Vec<Staff> = client
            .query(query)
            .bind(("user_uuid", user_uuid))
            .bind(("establishment_uuid", establishment_uuid))
            .await?
            .take(0)?;

        if !existing.is_empty() {
            return Err(SurrealSocketError::new(
                "User is already a Staff for this establishment.",
            ));
        }

        Ok(())
    }
}

impl Staff {
    pub fn new(user: &SsUuid<User>, establishment: &SsUuid<Establishment>) -> Self {
        Self {
            uuid: SsUuid::new(),
            user: user.to_owned(),
            establishment: establishment.to_owned(),
        }
    }

    pub async fn get_permissions(&self) -> Result<Vec<StaffPermissionKind>, Error> {
        let client = surrealdb_client().await?;

        Ok(
            StaffPermission::db_search(&client, "staff", self.uuid.to_string())
                .await?
                .into_iter()
                .map(|p| p.kind)
                .collect::<Vec<StaffPermissionKind>>(),
        )
    }

    pub async fn set_permissions(
        &mut self,
        new_permissions: Vec<StaffPermissionKind>,
    ) -> Result<(), Error> {
        let client = surrealdb_client().await?;
        let existing_permissions = StaffPermission::get_belonging_to(&self.uuid).await?;

        for permission in existing_permissions {
            if !new_permissions.contains(&permission.kind) {
                permission.db_delete(&client).await?;
            }
        }

        for permission in new_permissions {
            self.set_permission(permission).await?;
        }

        Ok(())
    }

    pub async fn set_permission(&mut self, permission: StaffPermissionKind) -> Result<(), Error> {
        let client = surrealdb_client().await?;
        let existing_permissions = StaffPermission::get_belonging_to(&self.uuid).await?;

        if !existing_permissions.iter().any(|p| p.kind == permission) {
            StaffPermission::new(&self.uuid, permission)
                .db_create(&client)
                .await?;
        }

        Ok(())
    }

    pub async fn get_user(&self) -> Result<User, Error> {
        let client = surrealdb_client().await?;

        match self.user.db_fetch_opt(&client).await? {
            Some(user) => Ok(user),
            None => {
                self.db_delete(&client).await?;
                Err(Error::generic_500(&format!(
                    "Illegal state: User not found for staff {}. Staff deleted.",
                    self.uuid
                )))
            }
        }
    }

    pub async fn has_permission(&self, permission: StaffPermissionKind) -> Result<bool, Error> {
        let permissions = self.get_permissions().await?;
        Ok(permissions.contains(&permission))
    }

    pub async fn current_schedule_entry(&self) -> Result<Option<StaffScheduleEntry>, Error> {
        let now = chrono::Utc::now().date_naive();
        self.get_schedule_entry(now).await
    }

    pub async fn current_shift(&self) -> Result<Option<TimePeriod>, Error> {
        let mut schedule_entries = vec![];
        let now = chrono::Utc::now();

        // Today and yesterday (Since yesterday's shifts could be ongoing)
        for i in 0..2 {
            let date = now
                .checked_sub_signed(chrono::Duration::days(i))
                .ok_or_else(|| Error::generic_500("Date out of range"))?
                .date_naive();

            if let Some(entry) = self.get_schedule_entry(date).await? {
                schedule_entries.push(entry);
            }
        }

        let current_minute = (now.time().num_seconds_from_midnight() / 60) as u16;

        for schedule_entry in schedule_entries {
            for shift in schedule_entry.shifts {
                let (begin, end) = if shift.end() > MINUTES_IN_DAY {
                    (0, shift.end() - MINUTES_IN_DAY)
                } else {
                    (shift.start(), shift.end())
                };

                if begin <= current_minute && current_minute <= end {
                    return Ok(Some(shift));
                }
            }
        }

        Ok(None)
    }

    pub async fn working_until(&self) -> Result<Option<u16>, Error> {
        Ok(self.current_shift().await?.map(|period| period.end()))
    }

    pub async fn get_schedule_entry(
        &self,
        date: NaiveDate,
    ) -> Result<Option<StaffScheduleEntry>, Error> {
        let client = surrealdb_client().await?;

        let query = format!(
            "SELECT * FROM {} WHERE date = $date AND staff = $staff;",
            StaffScheduleEntry::table()
        );

        let entry: Vec<StaffScheduleEntry> = client
            .query(query)
            .bind(("date", date))
            .bind(("staff", self.uuid.to_string()))
            .await?
            .take(0)?;

        if entry.is_empty() {
            return Ok(None);
        }

        if entry.len() > 1 {
            return Err(Error::generic_500(&format!(
                "Illegal state: Multiple schedule entries found for staff {} on date {}.",
                self.uuid, date
            )));
        }

        Ok(Some(entry[0].clone()))
    }

    pub async fn check_in(&self, start: u16, end: u16) -> Result<(), Error> {
        let period = TimePeriod::new(start, end)?;

        let mut schedule = match self.current_schedule_entry().await? {
            Some(schedule) => schedule,
            None => StaffScheduleEntry::new(chrono::Utc::now().date_naive()),
        };

        schedule.add_shift(period)?;
        let client = surrealdb_client().await?;
        schedule.db_overwrite(&client).await?;
        Ok(())
    }

    pub async fn check_out(&self, minute: u16) -> Result<(), Error> {
        let mut schedule = match self.current_schedule_entry().await? {
            Some(schedule) => schedule,
            None => return Err(Error::generic_500("No current schedule entry found.")),
        };

        if let Some(shift_index) = schedule
            .shifts
            .iter()
            .position(|shift| shift.start() <= minute && minute <= shift.end())
        {
            schedule.shifts.remove(shift_index);
            let client = surrealdb_client().await?;
            schedule.db_overwrite(&client).await?;
            Ok(())
        } else {
            Err(Error::generic_500("No shift found for the given time."))
        }
    }
}
