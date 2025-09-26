use crate::generic::DisplayName;
use crate::generic::GenericResponse;
use crate::generic::PhoneNumber;
use crate::generic::UniqueHandle;
use crate::models::establishment::Coordinate;
use crate::models::establishment::Establishment;
use crate::models::establishment::EstablishmentRating;
use crate::models::establishment::Schedule;
use crate::models::review::Review;
use crate::models::review::ReviewBody;
use crate::models::review::ReviewContext;
use crate::models::review::ReviewRating;
use crate::models::staff::Staff;
use crate::models::staff_permission::StaffPermissionKind;
use crate::models::user::User;
use crate::routes::openapi::DummySuccess;
use crate::routes::openapi::HandleDummy;
use crate::{
    error::Error,
    generic::{surrealdb_client, BearerToken},
};
use core::str;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use serde::Deserialize;
use std::str::FromStr;
use strum::AsRefStr;
use surreal_socket::dbrecord::DBRecord;
use surreal_socket::dbrecord::SsUuid;
use utoipa::ToSchema;

/// Establishment Card - Minimal establishment info for search results
#[derive(Serialize, ToSchema)]
pub struct EstablishmentCard {
    uuid: String,
    display_name: DisplayName,
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    handle: UniqueHandle<HandleDummy>,
    rating: EstablishmentRating,
    address: String,
    phone_number: Option<PhoneNumber>,
}

impl From<Establishment> for EstablishmentCard {
    fn from(establishment: Establishment) -> Self {
        Self {
            uuid: establishment.uuid.to_uuid_string(),
            display_name: establishment.display_name,
            handle: UniqueHandle::new_unchecked(establishment.handle.to_string()),
            rating: establishment.rating,
            address: establishment.address,
            phone_number: establishment.phone_number,
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
    pub rating: Option<EstablishmentRating>,
    pub address: Option<String>,
    pub phone_number: Option<PhoneNumber>,
}

/// Establishment Response
#[derive(Serialize, ToSchema)]
pub struct EstablishmentResponse {
    pub uuid: String,
    pub display_name: DisplayName,
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    pub handle: UniqueHandle<HandleDummy>,
    pub schedule: Schedule,
    pub coordinate: Coordinate,
    pub rating: EstablishmentRating,
    pub address: String,
    pub phone_number: Option<PhoneNumber>,
    pub staff: Vec<EstablishmentStaffResponse>,
    pub reviews: Vec<EstablishmentReviewResponse>,
}

impl EstablishmentResponse {
    pub async fn from_establishment(establishment: Establishment) -> Result<Self, Error> {
        let staff = establishment.get_staff().await?;
        let mut staff_response = Vec::with_capacity(staff.len());

        for staff in staff {
            let user = staff.get_user().await?;

            staff_response.push(EstablishmentStaffResponse {
                user_uuid: user.uuid.to_uuid_string(),
                display_name: user.display_name,
                handle: user.username,
                permissions: staff.get_permissions().await?,
                working_until: staff.working_until().await?,
            });
        }

        let reviews = Review::db_search(
            &surrealdb_client().await?,
            "context",
            ReviewContext::EstablishmentReview(establishment.uuid.clone()),
        )
        .await?;

        let mut reviews_response = Vec::with_capacity(reviews.len());

        for review in reviews {
            let user = review.get_user().await?;

            reviews_response.push(EstablishmentReviewResponse {
                user_uuid: user.uuid.to_uuid_string(),
                display_name: user.display_name,
                handle: user.username,
                rating: review.rating,
                body: review.body,
            });
        }

        Ok(Self {
            uuid: establishment.uuid.to_uuid_string(),
            display_name: establishment.display_name,
            handle: UniqueHandle::new_unchecked(establishment.handle.to_string()),
            schedule: establishment.schedule,
            coordinate: establishment.coordinate,
            rating: establishment.rating,
            address: establishment.address,
            phone_number: establishment.phone_number,
            staff: staff_response,
            reviews: reviews_response,
        })
    }
}

#[derive(Serialize, ToSchema)]
pub struct EstablishmentStaffResponse {
    pub user_uuid: String,
    pub display_name: DisplayName,
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    pub handle: UniqueHandle<User>,
    pub permissions: Vec<StaffPermissionKind>,
    /// Null if the Staff is not currently checked in.
    pub working_until: Option<u16>,
}

#[derive(Serialize, ToSchema)]
pub struct EstablishmentReviewResponse {
    pub user_uuid: String,
    pub display_name: DisplayName,
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    pub handle: UniqueHandle<User>,
    pub rating: ReviewRating,
    pub body: Option<ReviewBody>,
}

/// Create Establishment
#[utoipa::path(
    post,
    path = "/v1/establishments",
    description = "Create an Establishment. Admins only.",
    request_body(content = EstablishmentRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Fetched Establishment", body = EstablishmentResponse),
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
    let request_user = bearer_token.validate().await?.user().await?;

    if !request_user.is_admin {
        return Err(Error::forbidden().into());
    }

    let new_establishment = Establishment::try_from_request(request.0).await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    new_establishment
        .db_create(&client)
        .await
        .map_err(Error::from)?;

    Ok(Json(
        EstablishmentResponse::from_establishment(new_establishment).await?,
    ))
}

/// Get Establishment
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
    id_or_handle: &str,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
    match Establishment::by_id_or_handle(id_or_handle).await? {
        Some(establishment) => Ok(Json(
            EstablishmentResponse::from_establishment(establishment).await?,
        )),
        None => Err(Error::not_found("Establishment not found").into()),
    }
}

/// Update Establishment
#[utoipa::path(
    patch,
    path = "/v1/establishments/{establishment_id}",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID")
    ),
    description = "Update an Establishment if the User is a Staff with sufficient permissions (or is an admin)",
    request_body(content = EstablishmentRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Updated Establishment", body = EstablishmentResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::patch("/v1/establishments/<establishment_id>", data = "<request>")]
pub async fn update_establishment(
    request: Json<EstablishmentRequest>,
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let mut establishment = establishment_id
        .db_fetch(&client)
        .await
        .map_err(Error::from)?;

    let mut allowed = false;

    if request_user.is_admin {
        allowed = true;
    } else if let Some(staff) = request_user.staff_at(&establishment_id).await? {
        if staff.has_permission(StaffPermissionKind::Admin).await? {
            allowed = true;
        }
    }

    if !allowed {
        return Err(Error::forbidden().into());
    }

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
        .map_err(Error::from)?;

    Ok(Json(
        EstablishmentResponse::from_establishment(establishment).await?,
    ))
}

/// Search Establishments
#[utoipa::path(
    post,
    path = "/v1/establishments/search",
    description = "Returns Establishment cards with minimal info. Use `GET /v1/establishments/<id_or_handle>` to get full details.",
    request_body(content = EstablishmentSearchRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "List of Establishment cards", body = [EstablishmentCard]),
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
        let all_establishments = Establishment::db_all(&client).await?;
        let matcher = SkimMatcherV2::default();

        let mut result_establishments: Vec<_> = all_establishments
            .into_iter()
            .filter_map(|e| {
                matcher
                    .fuzzy_match(&e.display_name.to_string(), &name)
                    .map(|score| (score, e))
            })
            .collect();

        result_establishments.sort_by_key(|(score, _)| *score);
        result_establishments.reverse();

        let results: Vec<_> = result_establishments.into_iter().map(|(_, e)| e).collect();
        return Ok(results);
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
                FROM establishments
                WHERE geo::distance(surreal_geo_point, {{
                        type: "Point",
                        coordinates: [{}, {}]
                    }}) < {}
                ORDER BY {} DESC
                LIMIT 200;
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
            "SELECT * FROM {} ORDER BY {} DESC LIMIT 200;",
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

/// Delete Establishment
#[utoipa::path(
    delete,
    path = "/v1/establishments/{establishment_id}",
    description = "Delete an Establishment by ID",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID")
    ),
    responses(
        (status = 200, description = "Establishment deleted", body = EstablishmentResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::delete("/v1/establishments/<establishment_id>")]
pub async fn delete_establishment(
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;
    let mut allowed = false;

    if request_user.is_admin {
        allowed = true;
    } else if let Some(staff) = request_user.staff_at(&establishment_id).await? {
        if staff.has_permission(StaffPermissionKind::Admin).await? {
            allowed = true;
        }
    }

    if !allowed {
        return Err(Error::forbidden().into());
    }

    let establishment = establishment_id
        .db_fetch(&client)
        .await
        .map_err(Error::from)?;

    establishment
        .db_delete(&client)
        .await
        .map_err(Error::from)?;

    Ok(Json(
        EstablishmentResponse::from_establishment(establishment).await?,
    ))
}

/// Establishment Staff Update Request
#[derive(Deserialize, ToSchema)]
pub struct EstablishmentStaffUpdateRequest {
    /// Any permission not included in this list will be removed if they were previously on the Staff.
    pub new_permissions: Vec<StaffPermissionKind>,
}

/// Update Staff
#[utoipa::path(
    patch,
    path = "/v1/establishments/{establishment_id}/staff/{user_id}",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
        ("user_id" = String, Path, description = "Staff User ID")
    ),
    description = "Update an Establishment's Staff's permissions if the requesting User is a Staff with sufficient permissions (or is an admin)",
    request_body(content = EstablishmentStaffUpdateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Updated Establishment Staff", body = EstablishmentStaffResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::patch(
    "/v1/establishments/<establishment_id>/staff/<user_id>",
    data = "<request>"
)]
pub async fn update_establishment_staff(
    request: Json<EstablishmentStaffUpdateRequest>,
    establishment_id: &str,
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<EstablishmentStaffResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let establishment = establishment_id
        .db_fetch(&client)
        .await
        .map_err(Error::from)?;

    let mut allowed = false;

    if request_user.is_admin {
        allowed = true;
    } else if let Some(staff) = request_user.staff_at(&establishment_id).await? {
        if staff.has_permission(StaffPermissionKind::Admin).await? {
            allowed = true;
        }
    }

    if !allowed {
        return Err(Error::forbidden().into());
    }

    let mut staff = match establishment.get_staff_by_user_id(user_id).await? {
        Some(staff) => staff,
        None => return Err(Error::not_found("Staff not found").into()),
    };

    let staff_user = staff.get_user().await?;

    staff
        .set_permissions(request.new_permissions.clone())
        .await?;

    Ok(Json(EstablishmentStaffResponse {
        user_uuid: staff_user.uuid.to_uuid_string(),
        display_name: staff_user.display_name,
        handle: staff_user.username,
        permissions: staff.get_permissions().await?,
        working_until: staff.working_until().await?,
    }))
}

/// Add Staff
#[utoipa::path(
    put,
    path = "/v1/establishments/{establishment_id}/staff/{user_id}",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
        ("user_id" = String, Path, description = "Staff User ID")
    ),
    description = "Add a User as Staff to an Establishment if the requesting User is a Staff with sufficient permissions (or is an admin)",
    responses(
        (status = 200, description = "Updated Establishment", body = EstablishmentResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::put("/v1/establishments/<establishment_id>/staff/<user_id>")]
pub async fn add_establishment_staff(
    establishment_id: &str,
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<EstablishmentResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let establishment: Establishment = establishment_id
        .db_fetch(&client)
        .await
        .map_err(Error::from)?;

    let mut allowed = false;

    if request_user.is_admin {
        allowed = true;
    } else if let Some(staff) = request_user.staff_at(&establishment_id).await? {
        if staff.has_permission(StaffPermissionKind::Admin).await? {
            allowed = true;
        }
    }

    if !allowed {
        return Err(Error::forbidden().into());
    }

    let establishment_staff = Staff::db_search(
        &client,
        "establishment",
        establishment.uuid.to_uuid_string(),
    )
    .await
    .map_err(Error::from)?;

    for staff in establishment_staff {
        if staff.user.to_uuid_string() == user_id {
            return Err(Error::bad_request("User is already Staff at this Establishment").into());
        }
    }

    Staff::new(
        &SsUuid::from_str(user_id).map_err(Error::from)?,
        &establishment.uuid,
    )
    .db_create(&client)
    .await
    .map_err(Error::from)?;

    Ok(Json(
        EstablishmentResponse::from_establishment(establishment).await?,
    ))
}

/// Delete Staff
#[utoipa::path(
    delete,
    path = "/v1/establishments/{establishment_id}/staff/{user_id}",
    description = "Delete an Establishment's Staff by the User ID",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
        ("user_id" = String, Path, description = "Staff User ID"),
    ),
    responses(
        (status = 200, description = "Establishment Staff deleted", body = EstablishmentStaffResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::delete("/v1/establishments/<establishment_id>/staff/<user_id>")]
pub async fn delete_establishment_staff(
    establishment_id: &str,
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<EstablishmentStaffResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let establishment = establishment_id
        .db_fetch(&client)
        .await
        .map_err(Error::from)?;

    let mut allowed = false;

    if request_user.is_admin {
        allowed = true;
    } else if let Some(staff) = request_user.staff_at(&establishment_id).await? {
        if staff.has_permission(StaffPermissionKind::Admin).await? {
            allowed = true;
        }
    }

    if !allowed {
        return Err(Error::forbidden().into());
    }

    let staff = match establishment.get_staff_by_user_id(user_id).await? {
        Some(staff) => staff,
        None => return Err(Error::not_found("Staff not found").into()),
    };

    let staff_user = staff.get_user().await?;

    let response = EstablishmentStaffResponse {
        user_uuid: staff_user.uuid.to_uuid_string(),
        display_name: staff_user.display_name,
        handle: staff_user.username,
        permissions: staff.get_permissions().await?,
        working_until: staff.working_until().await?,
    };

    staff.db_delete(&client).await.map_err(Error::from)?;

    Ok(Json(response))
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ReviewDto {
    pub rating: ReviewRating,
    pub body: Option<ReviewBody>,
}

/// Add Review
#[utoipa::path(
    post,
    path = "/v1/establishments/{establishment_id}/review",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
    ),
    description = "Add a Review to an Establishment",
    request_body(content = ReviewDto, content_type = "application/json"),
    responses(
        (status = 200, description = "Added Establishment Review", body = ReviewDto),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::post("/v1/establishments/<establishment_id>/review", data = "<request>")]
pub async fn add_establishment_review(
    request: Json<ReviewDto>,
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<ReviewDto>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let establishment = establishment_id
        .db_fetch(&client)
        .await
        .map_err(Error::from)?;

    if request_user.staff_at(&establishment_id).await?.is_some() {
        return Err(Error::new(
            rocket::http::Status::Forbidden,
            "Staff cannot review their own Establishment",
            None,
        )
        .into());
    }

    let user_reviews = Review::db_search(&client, "user", request_user.uuid.to_uuid_string())
        .await
        .map_err(Error::from)?;

    for review in user_reviews {
        if let ReviewContext::EstablishmentReview(establishment_review_id) = review.context {
            if establishment_review_id == establishment_id {
                return Err(
                    Error::bad_request("User has already reviewed this establishment").into(),
                );
            }
        }
    }

    let review = Review::new(
        &request_user.uuid,
        ReviewContext::EstablishmentReview(establishment.uuid.clone()),
        request.rating.clone(),
        request.body.clone(),
    );

    review.validate()?;

    review.db_create(&client).await.map_err(Error::from)?;

    Ok(request)
}

/// Update Review
#[utoipa::path(
    patch,
    path = "/v1/establishments/{establishment_id}/review",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
    ),
    description = "Update the Establishment Review for the requesting User",
    request_body(content = ReviewDto, content_type = "application/json"),
    responses(
        (status = 200, description = "Updated Establishment Review", body = ReviewDto),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::patch("/v1/establishments/<establishment_id>/review", data = "<request>")]
pub async fn update_establishment_review(
    request: Json<ReviewDto>,
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<ReviewDto>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let user_reviews = Review::db_search(&client, "user", request_user.uuid.to_uuid_string())
        .await
        .map_err(Error::from)?;

    for review in user_reviews {
        if let ReviewContext::EstablishmentReview(establishment_review_id) = &review.context {
            if establishment_review_id == &establishment_id {
                let mut review = review;
                review.rating = request.rating.clone();
                review.body = request.body.clone();
                review.validate()?;

                review.db_overwrite(&client).await.map_err(Error::from)?;

                return Ok(request);
            }
        }
    }

    Err(Error::bad_request("User has not reviewed this establishment").into())
}

/// Delete Review
#[utoipa::path(
    delete,
    path = "/v1/establishments/{establishment_id}/review",
    description = "Delete the Establishment Review for the requesting User",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
    ),
    responses(
        (status = 200, description = "Establishment Review deleted", body = ReviewDto),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::delete("/v1/establishments/<establishment_id>/review")]
pub async fn delete_establishment_review(
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<ReviewDto>, status::Custom<Json<GenericResponse>>> {
    let establishment_id = SsUuid::from_str(establishment_id).map_err(Error::from)?;
    let request_user = bearer_token.validate().await?.user().await?;
    let client = surrealdb_client().await.map_err(Error::from)?;

    let user_reviews = Review::db_search(&client, "user", request_user.uuid.to_uuid_string())
        .await
        .map_err(Error::from)?;

    for review in user_reviews {
        if let ReviewContext::EstablishmentReview(establishment_review_id) = &review.context {
            if establishment_review_id == &establishment_id {
                let response = ReviewDto {
                    rating: review.rating.clone(),
                    body: review.body.clone(),
                };

                review.db_delete(&client).await.map_err(Error::from)?;

                return Ok(Json(response));
            }
        }
    }

    Err(Error::bad_request("User has not reviewed this establishment").into())
}

/// Check-in Request
#[derive(Deserialize, ToSchema)]
pub struct CheckinRequest {
    /// Start time of the working shift in minutes since midnight (UTC).
    ///
    /// For quick check-ins, this can be set to the current time.
    /// The frontend should set this on page load to avoid bugs when the page is loaded just before midnight.
    start: u16,

    /// In minutes since midnight (UTC). Can be over 1440 if working until after midnight.
    end: u16,

    /// Optional User ID to check in. If not provided, the requesting User is checked in.
    user_id: Option<String>,
}

/// Staff Check in
#[utoipa::path(
    post,
    path = "/v1/establishments/{establishment_id}/checkin",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
    ),
    description = "Check in the requesting User if they are a Staff of the Establishment",
    request_body(content = CheckinRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "OK", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::post("/v1/establishments/<establishment_id>/checkin", data = "<request>")]
pub async fn check_in(
    request: Json<CheckinRequest>,
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<GenericResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id: SsUuid<Establishment> =
        SsUuid::from_str(establishment_id).map_err(Error::from)?;

    let requester = bearer_token.validate().await?.user().await?;

    let user = if let Some(user_id) = &request.user_id {
        if let Some(staff) = requester.staff_at(&establishment_id).await? {
            if !staff.has_permission(StaffPermissionKind::Admin).await? {
                return Err(Error::insufficient_permissions().into());
            }
        } else {
            return Err(
                Error::not_found("Requesting User is not Staff at this Establishment").into(),
            );
        }

        let client = surrealdb_client().await.map_err(Error::from)?;

        User::db_get_by_id(&client, user_id)
            .await
            .map_err(Error::from)?
            .ok_or_else(|| Error::not_found("User not found"))?
    } else {
        requester
    };

    let staff = match user.staff_at(&establishment_id).await? {
        Some(staff) => staff,
        None => return Err(Error::not_found("User is not Staff at this Establishment").into()),
    };

    staff.check_in(request.start, request.end).await?;
    Ok(Json(GenericResponse::success()))
}

/// Check-out Request
#[derive(Deserialize, ToSchema)]
pub struct CheckoutRequest {
    /// Time in minutes since midnight of any minute within the shift, inclusive of start/end times (UTC).
    time: u16,
    user_id: Option<String>,
}

/// Staff Check out
#[utoipa::path(
    post,
    path = "/v1/establishments/{establishment_id}/checkout",
    params(
        ("establishment_id" = String, Path, description = "Establishment ID"),
    ),
    description = "Check out the requesting User if they are a Staff of the Establishment",
    request_body(content = CheckoutRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "OK", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "establishment"
)]
#[rocket::post("/v1/establishments/<establishment_id>/checkout", data = "<request>")]
pub async fn check_out(
    request: Json<CheckoutRequest>,
    establishment_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<GenericResponse>, status::Custom<Json<GenericResponse>>> {
    let establishment_id: SsUuid<Establishment> =
        SsUuid::from_str(establishment_id).map_err(Error::from)?;

    let requester = bearer_token.validate().await?.user().await?;

    let user = if let Some(user_id) = &request.user_id {
        if let Some(staff) = requester.staff_at(&establishment_id).await? {
            if !staff.has_permission(StaffPermissionKind::Admin).await? {
                return Err(Error::insufficient_permissions().into());
            }
        } else {
            return Err(
                Error::not_found("Requesting User is not Staff at this Establishment").into(),
            );
        }

        let client = surrealdb_client().await.map_err(Error::from)?;

        User::db_get_by_id(&client, user_id)
            .await
            .map_err(Error::from)?
            .ok_or_else(|| Error::not_found("User not found"))?
    } else {
        requester
    };

    let staff = match user.staff_at(&establishment_id).await? {
        Some(staff) => staff,
        None => return Err(Error::not_found("User is not Staff at this Establishment").into()),
    };

    staff.check_out(request.time).await?;
    Ok(Json(GenericResponse::success()))
}
