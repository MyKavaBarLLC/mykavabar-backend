use crate::generic::EmailAddress;
use crate::generic::PhoneNumber;
use crate::models::staff::Staff;
use crate::models::staff_permission::StaffPermissionKind;
use crate::routes::establishment::EstablishmentCard;
use crate::routes::openapi::DummySuccess;
use crate::routes::openapi::HandleDummy;
use crate::{
    error::Error,
    generic::{surrealdb_client, BearerToken, DisplayName, GenericResponse, UniqueHandle},
    models::{session::Session, user::User},
    routes::token::{token, TokenRequest, TokenResponse},
};
use core::str;
use rocket::{
    http::Status,
    response::status,
    serde::{json::Json, Deserialize},
};
use serde::Serialize;
use serde_json::json;
use surreal_socket::dbrecord::DBRecord;
use utoipa::ToSchema;

/// User Response
#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub uuid: String,
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    pub username: UniqueHandle<HandleDummy>,
    pub display_name: DisplayName,
    pub is_admin: bool,
    pub phone_number: Option<PhoneNumber>,
    pub avatar_url: Option<String>,
    pub email: EmailAddress,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub staff_roles: Vec<UserResponseStaffRole>,
}

impl UserResponse {
    pub async fn from_user(user: User) -> Result<Self, Error> {
        let staff = user.get_staff().await?;
        let mut staff_roles = Vec::with_capacity(staff.len());

        for staff in staff {
            let staff_role = UserResponseStaffRole::from_staff(staff).await?;
            staff_roles.push(staff_role);
        }

        Ok(Self {
            uuid: user.uuid.to_uuid_string(),
            username: UniqueHandle::new_unchecked(user.username.to_string()),
            display_name: user.display_name,
            is_admin: user.is_admin,
            phone_number: user.phone_number,
            email: user.email,
            avatar_url: None, // todo
            first_name: user.first_name,
            last_name: user.last_name,
            staff_roles,
        })
    }
}

/// A Staff link as it appears in the UserResponse
#[derive(Serialize, ToSchema)]
pub struct UserResponseStaffRole {
    pub establishment: EstablishmentCard,
    pub permissions: Vec<StaffPermissionKind>,
}

impl UserResponseStaffRole {
    pub async fn from_staff(staff: Staff) -> Result<Self, Error> {
        let client = surrealdb_client().await?;

        let establishment = match staff.establishment.db_fetch_opt(&client).await? {
            Some(establishment) => establishment,
            None => {
                staff.db_delete(&client).await?;

                return Err(Error::generic_500(&format!(
                        "Illegal state: Staff {} linked to non-existent establishment: {}. Staff deleted.",
                        staff.uuid,
                        staff.establishment
                    )));
            }
        };

        Ok(Self {
            establishment: EstablishmentCard::from(establishment),
            permissions: staff.get_permissions().await?,
        })
    }
}

/// Get User
#[utoipa::path(
    get,
    path = "/v1/users/{user_id}",
    description = "Get a full User by ID. Only available to admins or the user themselves. If the ID is 'me', the session's user is returned.",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User fetched", body = UserResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::get("/v1/users/<user_id>")]
pub async fn get_user(
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<UserResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let user = get_user_as_self_or_admin(user_id, session).await?;
    Ok(Json(UserResponse::from_user(user).await?))
}

/// Registration Request
#[derive(Deserialize, ToSchema)]
pub struct RegistrationRequest {
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    pub username: UniqueHandle<HandleDummy>,
    pub display_name: DisplayName,
    pub password: String,
    pub email: EmailAddress,
}

/// Register User
#[utoipa::path(
    post,
    path = "/v1/register_user",
    description = "Register a new User",
    request_body(content = RegistrationRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "User registered and token granted", body = TokenResponse),
        (status = 400, description = "Bad request", body = GenericResponse)
    ),
    tag = "auth"
)]
#[rocket::post("/v1/register_user", format = "json", data = "<registration>")]
pub async fn register(
    registration: Json<RegistrationRequest>,
) -> Result<Json<TokenResponse>, status::Custom<Json<GenericResponse>>> {
    let registration = registration.into_inner();
    let user = User::register(&registration).await?;

    // Log them in
    let token_request =
        TokenRequest::new_password_grant(&user.username.to_string(), &registration.password);

    token(token_request).await
}

/// Retrieves a user by their ID, subject to security checks based on the session.
///
/// This function accepts a user ID and a session. If the ID is "me", it returns the session's user.
/// Otherwise, it returns the user corresponding to the provided ID only if the session's user is
/// the same as the user with the ID or if the session's user is an admin.
async fn get_user_as_self_or_admin(id: &str, session: Session) -> Result<User, Error> {
    if id == "me" {
        session.user().await
    } else {
        match User::db_get_by_id(&surrealdb_client().await?, id).await? {
            Some(target_user) => {
                let session_user = session.user().await?;

                if target_user.uuid != session_user.uuid() && !session_user.is_admin {
                    return Err(Error::insufficient_permissions());
                }

                Ok(target_user)
            }
            None => Err(Error::new(Status::NotFound, "User not found", None)),
        }
    }
}

/// Change password request
#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[utoipa::path(
    post,
    path = "/v1/users/{user_id}/change_password",
    description = "Change password",
    request_body(content = ChangePasswordRequest, content_type = "application/json"),
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Password changed", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::post(
    "/v1/users/<user_id>/change_password",
    format = "json",
    data = "<request>"
)]
pub async fn change_password(
    user_id: &str,
    request: Json<ChangePasswordRequest>,
    bearer_token: BearerToken,
) -> Result<Json<GenericResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let mut user = get_user_as_self_or_admin(user_id, session).await?;

    if user.verify_password(&request.old_password).is_err() {
        return Err(Error::new(Status::Unauthorized, "Invalid password", None).into());
    }

    user.set_password(&request.new_password).await?;
    Ok(Json(GenericResponse::success()))
}

/// User Request
#[derive(Deserialize, ToSchema)]
pub struct UserRequest {
    /// Unique, mutable handle used in URLs. Must be lowercase, alphanumeric, and may include underscores.
    #[schema(value_type = String)]
    pub username: Option<UniqueHandle<HandleDummy>>,
    pub display_name: Option<DisplayName>,

    /// Only admins can change the password of a user with this endpoint.
    /// Users can change their own password by using the change_password endpoint.
    /// This is because users must provide their current password to change it.
    pub password: Option<String>,
}

/// Update User
#[utoipa::path(
    patch,
    path = "/v1/users/{user_id}",
    description = "Update a User by ID",
    request_body(content = UserRequest, content_type = "application/json"),
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 400, description = "Bad request", body = GenericResponse),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::patch("/v1/users/<user_id>", format = "json", data = "<request>")]
pub async fn update_user(
    user_id: &str,
    request: Json<UserRequest>,
    bearer_token: BearerToken,
) -> Result<Json<UserResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let mut user = get_user_as_self_or_admin(user_id, session).await?;
    let mut updates = vec![];

    if let Some(username) = &request.username {
        let handle = UniqueHandle::<User>::new(&username.to_string()).await?;
        updates.push(("username", json!(handle)));
        user.username = handle.to_owned();
    }

    if let Some(display_name) = &request.display_name {
        display_name.validate()?;
        updates.push(("display_name", json!(display_name)));
        user.display_name = display_name.to_owned();
    }

    if let Some(password) = &request.password {
        if user.is_admin {
            user.set_password(password).await?;
        } else {
            return Err(Error::bad_request(
                "Users can only change their own password with the change_password endpoint",
            )
            .into());
        }
    }

    user.db_update_fields(&surrealdb_client().await.map_err(Error::from)?, updates)
        .await
        .map_err(Error::from)?;

    Ok(Json(UserResponse::from_user(user).await?))
}

/// Delete User
#[utoipa::path(
    delete,
    path = "/v1/users/{user_id}",
    description = "Delete a User by ID",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User deleted", body = DummySuccess),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::delete("/v1/users/<user_id>")]
pub async fn delete_user(
    user_id: &str,
    bearer_token: BearerToken,
) -> Result<Json<GenericResponse>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let user = get_user_as_self_or_admin(user_id, session).await?;

    user.db_delete(&surrealdb_client().await.map_err(Error::from)?)
        .await
        .map_err(Error::from)?;

    Ok(Json(GenericResponse::success()))
}

/// Get all Users
#[utoipa::path(
    get,
    path = "/v1/users",
    description = "Get all Users. Only available to admins.",
    responses(
        (status = 200, description = "List of users", body = [UserResponse]),
        (status = 401, description = "Unauthorized", body = GenericResponse),
        (status = 403, description = "Forbidden", body = GenericResponse)
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "user"
)]
#[rocket::get("/v1/users")]
pub async fn get_users(
    bearer_token: BearerToken,
) -> Result<Json<Vec<UserResponse>>, status::Custom<Json<GenericResponse>>> {
    let session = bearer_token.validate().await?;
    let user = session.user().await?;

    if !user.is_admin {
        return Err(Error::insufficient_permissions().into());
    }

    let users = User::db_all(&surrealdb_client().await.map_err(Error::from)?)
        .await
        .map_err(Error::from)?;

    let mut response = Vec::with_capacity(users.len());

    for user in users {
        response.push(UserResponse::from_user(user).await?);
    }

    Ok(Json(response))
}
