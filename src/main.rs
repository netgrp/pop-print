mod auth;
mod print;

use std::{env, sync::Arc};

use axum::{
    Form, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Multipart, State, multipart::MultipartError},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    auth::{Authentication, KNetApiCreds, LoginError},
    print::{PrintOptions, Printer},
};

struct AppState {
    auth: Authentication,
    printer: Printer,
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "dotenv")]
    dotenv::dotenv().unwrap();

    let knet_api_creds = KNetApiCreds {
        api_base_url: Url::parse("https://api.k-net.dk/v2/").unwrap(),
        username: env::var("KNET_API_USERNAME").unwrap(),
        password: env::var("KNET_API_PASSWORD").unwrap(),
    };

    let key = env::var("AES_CRYPT_KEY").unwrap();
    let initialization_vector = env::var("INITIALIZATION_VECTOR")
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();

    let printer = Printer::new(env::var("PRINTER_URI").unwrap().parse().unwrap());

    let state = Arc::new(AppState {
        auth: Authentication::new(knet_api_creds, key.as_bytes(), initialization_vector).unwrap(),
        printer,
    });

    let app = Router::new()
        .route("/", get(root_page))
        .route(
            "/print",
            // We allow up to 1 GB of body for the print endpoint
            post(print_action).layer(DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .route("/login", get(login_page).post(login_action))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn has_valid_login_cookie(auth: &Authentication, cookie_jar: &CookieJar) -> bool {
    cookie_jar
        .get("login")
        .map_or(false, |cookie| auth.check_login(cookie.value()))
}

async fn root_page(state: State<Arc<AppState>>, cookie_jar: CookieJar) -> Response {
    if has_valid_login_cookie(&state.auth, &cookie_jar) {
        print_html()
    } else {
        Redirect::to("/login").into_response()
    }
}

#[derive(Debug, Error)]
enum PrintOptionExtractError {
    #[error("the {0} was not supplied")]
    MissingPrintOption(&'static str),
    #[error("document data was not supplied")]
    MissingDocument,
    #[error(transparent)]
    MultipartError(#[from] MultipartError),
}

async fn extract_print_data<'m>(
    multipart: &'m mut Multipart,
) -> Result<(Bytes, print::PrintOptions<'m>), PrintOptionExtractError> {
    use PrintOptionExtractError::*;

    let mut duplex = None;
    let mut color = None;
    let mut page_range = None;
    let mut orientation = None;
    let mut size = None;
    let mut copies = None;
    let mut file_contents = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name();
        eprintln!("got field name: {field_name:?}");
        match field_name {
            Some("duplex") => {
                duplex = Some(field.text().await?);
            }
            Some("color") => color = Some(field.text().await?),
            Some("range") => page_range = Some(field.text().await?),
            Some("orientation") => orientation = Some(field.text().await?),
            Some("size") => size = Some(field.text().await?),
            Some("copies") => {
                let text = field.text().await?;
                if text.is_empty() {
                    copies = Some(1)
                } else if let Ok(num) = text.parse() {
                    copies = Some(num);
                } else {
                    eprintln!("failed parsing copies: {text}")
                }
            }
            Some("uploadedPDF") => {
                file_contents = Some(field.bytes().await?);
            }
            Some(_) => {}
            None => {}
        };
    }

    let options = PrintOptions {
        duplex: duplex.ok_or(MissingPrintOption("duplex"))?.into(),
        color: color.ok_or(MissingPrintOption("color"))?.into(),
        page_range: page_range.ok_or(MissingPrintOption("range"))?.into(),
        orientation: orientation.ok_or(MissingPrintOption("orientation"))?.into(),
        size: size.ok_or(MissingPrintOption("size"))?.into(),
        copies: copies.ok_or(MissingPrintOption("copies"))?,
    };

    let file_contents = file_contents.ok_or(MissingDocument)?;

    Ok((file_contents, options))
}

async fn print_action(
    state: State<Arc<AppState>>,
    cookie_jar: CookieJar,
    mut multipart: Multipart,
) -> Response {
    if has_valid_login_cookie(&state.auth, &cookie_jar) {
        use PrintOptionExtractError::*;
        match extract_print_data(&mut multipart).await {
            Ok((file_contents, options)) => {
                match state.printer.print(options, &file_contents).await {
                    Ok(()) => Redirect::to("/").into_response(),
                    Err(err) => {
                        eprintln!("error whilst printing: {err}");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "There was error whilst printing",
                        )
                            .into_response()
                    }
                }
            }
            Err(MissingPrintOption(_) | MissingDocument) => {
                (StatusCode::BAD_REQUEST, "Missing form fields").into_response()
            }
            Err(MultipartError(err)) => err.into_response(),
        }
    } else {
        (StatusCode::UNAUTHORIZED, "Not logged in").into_response()
    }
}

async fn login_page(state: State<Arc<AppState>>, cookie_jar: CookieJar) -> Response {
    if has_valid_login_cookie(&state.auth, &cookie_jar) {
        Redirect::to("/").into_response()
    } else {
        login_html()
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_action(
    state: State<Arc<AppState>>,
    cookie_jar: CookieJar,
    Form(login): Form<LoginForm>,
) -> Response {
    match state.auth.login(&login.username, &login.password).await {
        Ok(login_cookie) => (
            cookie_jar.add(Cookie::new("login", login_cookie)),
            Redirect::to("/"),
        )
            .into_response(),
        Err(LoginError::HttpRequestError(error)) => {
            eprintln!("http request error while logging in: {:?}", error);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
        Err(LoginError::InvalidCredentials) => {
            (StatusCode::UNAUTHORIZED, "Invalid username/password").into_response()
        }
    }
}

fn print_html() -> Response {
    Html(include_str!("print_upload.html")).into_response()
}

fn login_html() -> Response {
    Html(include_str!("login.html")).into_response()
}
