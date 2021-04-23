use actix_web::{
    App,
    Error,
    HttpServer,
    HttpResponse,
    Responder,
    error,
    web, 
};
use actix_session::{CookieSession, Session};
use actix_web::http::header;
//use anyhow::Result;
use dotenv::dotenv;
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    EmptyExtraTokenFields,
    PkceCodeChallenge,
    PkceCodeVerifier,
    //RedirectUrl,
    //Scope,
    StandardTokenResponse,
    TokenResponse,
    TokenUrl,
};
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::reqwest::async_http_client;
use serde::{
    Deserialize,
    Serialize,
};
use std::env;
use std::fs::File;
use tracing::{error, event, instrument, Level};
use tracing_subscriber;

const PORT: i32 = 9090;
const MAL_API: &str = "https://api.myanimelist.net/v2";

#[derive(Debug)]
struct AppState {
    oauth_client: Box<BasicClient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnimeListEntryPictures {
    pub small: Option<String>,
    pub medium: Option<String>,
    pub large: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnimeListEntry {
    pub id: i64,
    pub title: String,
    pub main_picture: AnimeListEntryPictures
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Datum {
    pub node: AnimeListEntry,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Paging {
  pub previous: Option<String>,
  pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MyAnimeListResponse {
    pub data: Vec<Datum>,
    pub paging: Option<Paging>,
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
            .route("/mylist", web::get().to(mylist))
    })
    .bind(format!("127.0.0.1:{}", PORT))
    .expect(&format!("Can not bind to port {}", PORT))
    .run()
    .await?;
    Ok(())
}

#[instrument(skip(session))]
async fn index(session: Session) -> Result<HttpResponse, Error> {
    let logged_in: bool = match session.get::<bool>("login") {
        Ok(Some(x)) => { if x { true } else { false }},
        _ => false
    };
    let link: &str = if logged_in { "logout" } else { "login" };

    match session.get::<String>("anonId") {
        Ok(_) => (),
        Err(_) => session.insert("anonId", "1234abc").unwrap()
    }

    let access_frag = if logged_in {
        let token = session.get::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>("token")
            .unwrap().unwrap()
            .access_token()
            .secret()
            .clone();
        format!("Access token is {}", token)
    } else { "".to_string() };

    let mylist_frag = if logged_in { r#"<p><a href="/mylist">Anime List</a>"# } else { "" };
    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            <a href="/{0}">{0}</a>
            {1}
            <p>
            {2}
        </body>
    </html>"#,
        link, mylist_frag, access_frag
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
    session.insert("PKCE", pkce_challenge.as_str()).unwrap();
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
        .append_header((header::LOCATION, auth_url.to_string()))
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
        .append_header((header::LOCATION, "/".to_string()))
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

    let verifier = session.get::<PkceCodeVerifier>("PKCE")?.ok_or_else(|| error::ErrorBadRequest("No PKCE verifier found"))?;
    let token_req = data.oauth_client
        .exchange_code(code)
        .set_pkce_verifier(verifier);

    let token = token_req
        .request_async(async_http_client)
        .await
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;

    event!(Level::DEBUG, "token {:?}", &token);

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            API returned the following csrf state:
            <pre>{}</pre>
            API returned the following auth token:
            <pre>{:?}</pre>
            <a href="/">Home</a>
        </body>
    </html>"#,
        state.secret(),
        token.access_token().secret()
    );
    session.insert("token", token).unwrap();
    event!(Level::INFO, "token cookie set");
    session.insert("login", true).unwrap();
    Ok(HttpResponse::Ok().body(html))
}

#[instrument(skip(session))]
async fn mylist(
    session: Session,
    data: web::Data<AppState>,
) -> Result<web::Json<Vec<AnimeListEntry>>, Error> {
    event!(Level::INFO, "entered mylist route");
    let token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType> = session.get("token")?.ok_or_else(|| error::ErrorBadRequest("no token"))?;
    let client = reqwest::Client::new();
    let res = client.get(&(MAL_API.to_string() + "/users/@me/animelist"))
        .query(&[("limit", "1000")])
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| {
            error!("fetch failed, {}", &e);
            error::ErrorInternalServerError(e.to_string())
        })?;
    event!(Level::INFO, "successful MAL fetch");
    event!(Level::DEBUG, "my list response\n{:?}", &res);
    if res.status() != 200 {
        return Err(error::ErrorInternalServerError(format!("{:?}", res)));
    }
    let resp: MyAnimeListResponse = res.json()
        .await
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    let anime: Vec<AnimeListEntry> = resp.data.into_iter().map(|x| x.node).collect();
    serde_json::to_writer(&File::create("./data/animelist.json")?, &anime).map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    Ok(web::Json(anime))
}
