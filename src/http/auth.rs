use crate::utils::{
    decrypt_string,
    encrypt::{get_database_decrypted, EncryptionError},
};
use axum::{
    headers::{authorization::Basic, Authorization},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    TypedHeader,
};
use sqlite::State;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Error while encrypting the database: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("Error while querying: {0}")]
    SqliteError(#[from] sqlite::Error),
}

fn authenticate_user(username: String, password: String) -> Result<bool, AuthError> {
    let (db, _decryptor) = get_database_decrypted(None)?;

    let query = "SELECT * FROM user_creds";
    let mut statement = db.conn.prepare(query)?;

    while matches!(statement.next(), Ok(State::Row)) {
        let user_name_record = statement.read::<String, _>("user_name")?;
        let password_record = statement.read::<String, _>("password")?; // password is already
                                                                        // coming in the encrypted format

        if username == user_name_record
            && decrypt_string(password.as_str(), password_record.as_str())?
        {
            return Ok(true);
        }
    }

    Ok(false)
}

pub async fn auth<B>(
    TypedHeader(auth): TypedHeader<Authorization<Basic>>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, (StatusCode, String)> {
    let username = auth.username().to_string();
    let password = auth.password().to_string();

    // Check the username and password
    if !username.is_empty() && !password.is_empty() {
        let authenticate = match authenticate_user(username, password) {
            Ok(authenticate) => authenticate,
            Err(err) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Encountered error while authenticating user: {err}"),
                ));
            }
        };
        if authenticate {
            let response = next.run(request).await;
            Ok(response)
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                "Username Authentication failed".to_string(),
            ))
        }
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "Authorization header not found".to_string(),
        ))
    }
}
