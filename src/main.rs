use actix_web::{web, App, Error, HttpServer, HttpResponse, Responder};
use actix_session::{CookieSession, Session};
use actix_web::http::header;
use anyhow::Result;
use dotenv::dotenv;
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    PkceCodeChallenge,
    PkceCodeVerifier,
    //RedirectUrl,
    //Scope,
    //TokenResponse,
    TokenUrl,
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use serde::Deserialize;
use std::env;
use tracing::{event, instrument, Level};
use tracing_subscriber;

const PORT: i32 = 9090;

#[derive(Debug)]
struct AppState {
    oauth_client: Box<BasicClient>,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    let client_id = ClientId::new(env::var("CLIENT_ID".to_string())?);
    let client_secret = Some(ClientSecret::new(env::var("CLIENT_SECRET")?));
    let auth_url = AuthUrl::new(env::var("AUTH_URL")?)?;
    let token_url = Some(TokenUrl::new(env::var("TOKEN_URL")?)?);
    // let redirect_url = RedirectUrl::new(env::var("REDIRECT_URL")?)?;

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = Box::new(BasicClient::new
            (
                client_id,
                client_secret,
                auth_url,
                token_url
        )
        // Set the URL the user will be redirected to after the authorization process.
        // .set_redirect_url(redirect_url)
    );

    HttpServer::new(move || {
        App::new()
            .data(AppState { oauth_client: client.clone()})
            .wrap(CookieSession::signed(&[0; 32])
                .domain("mal.camcope.me")
                .name("mal")
                .secure(false)
                )
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/logout", web::get().to(logout))
            .route("/auth", web::get().to(auth))
    })
    .bind(format!("127.0.0.1:{}", PORT))
    .expect(&format!("Can not bind to port {}", PORT))
    .run()
    .await?;
    Ok(())
}

#[instrument(skip(session))]
async fn index(session: Session) -> Result<HttpResponse, Error> {
    let link: &str = match session.get::<bool>("login") {
        Ok(Some(x)) => { if x { "logout" } else { "login" } },
        _ => "login"
    };

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            <a href="/{}">{}</a>
        </body>
    </html>"#,
        link, link
    );

    Ok(HttpResponse::Ok().body(html))
}

#[instrument(skip(session))]
async fn login(
    session: Session,
    data: web::Data<AppState>,
    ) -> impl Responder {
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    // Generate a PKCE challenge.
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_plain();
    // TODO HAX HAX HAX XXX Uses "plain" pkce challenge type, where it just resends the original
    // code. Switch to sha256 when MAL supports it
    session.set("PKCE", pkce_challenge.as_str()).unwrap();
    event!(Level::DEBUG, "\n\nPKCE verifier is {}\n", session.get::<String>("PKCE").unwrap().unwrap());

    // Generate the full auth URL to which we'll redirect the user.
    let (auth_url, csrf_token) = &data.oauth_client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        //.add_scope(Scope::new("read".to_string()))
        //.add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    event!(Level::INFO, "\n\nCSRF token is {}", csrf_token.secret());
    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    HttpResponse::Found()
        .header(header::LOCATION, auth_url.to_string())
        .finish()
}

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // TODO: store csrf_token somehow to verify later
    // Redis? Cookies?


#[instrument(skip(session))]
async fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .header(header::LOCATION, "/".to_string())
        .finish()
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: Option<String>,
}

#[instrument(skip(session, params))]
async fn auth(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> Result<HttpResponse, Error> {
    event!(Level::INFO, "auth route: start");
    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());
    let _scope = params.scope.clone();
    event!(Level::INFO, "\nauth route:\n code {:?}\n csrf token {:?}", params.code.clone(), params.state.clone());

    let verifier = PkceCodeVerifier::new(session.get::<String>("PKCE").unwrap().unwrap());
    let token_req = data.oauth_client
        .exchange_code(code)
        .set_pkce_verifier(verifier);

    event!(Level::DEBUG, "token req:\n\n{:?}", &token_req);

    let token = token_req
        .request_async(async_http_client)
        .await
        .map_err(|e| HttpResponse::InternalServerError().body(&e.to_string()))?;

    event!(Level::INFO, "token {:?}", &token);

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            API returned the following csrf state:
            <pre>{}</pre>
            API returned the following auth token:
            <pre>{:?}</pre>
        </body>
    </html>"#,
        state.secret(),
        token
    );
    session.set("token", token).unwrap();
    event!(Level::INFO, "token cookie set");
    session.set("login", true).unwrap();
    Ok(HttpResponse::Ok().body(html))
}
