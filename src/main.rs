use actix_files::Files;
use actix_session::{CookieSession, Session};
use actix_web::http::header;
use actix_web::http::header::ContentType;
use actix_web::{error, web, App, Error, HttpResponse, HttpServer, Responder, Result};
use chrono::prelude::*;
use chrono::Duration;
use dotenv::dotenv;
use governor::{Quota, RateLimiter};
use mime::TEXT_HTML_UTF_8;
use nonzero_ext::nonzero;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl,
    AuthorizationCode,
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
use serde::Deserialize;
use std::env;
use std::fs::File;
use tracing::{error, event, instrument, Level};
use tracing_subscriber;
mod my_mal;
use crate::my_mal::*;

const PORT: i32 = 9090;
const MAL_API: &str = "https://api.myanimelist.net/v2";

#[derive(Debug)]
pub struct AppState {
    oauth_client: Box<BasicClient>,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: Option<String>,
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
    let client = Box::new(
        BasicClient::new(client_id, client_secret, auth_url, token_url),
        // Set the URL the user will be redirected to after the authorization process.
        // .set_redirect_url(redirect_url)
    );

    HttpServer::new(move || {
        App::new()
            .data(AppState {
                oauth_client: client.clone(),
            })
            .service(Files::new("/static", "./static").prefer_utf8(true).use_etag(true))
            .wrap(
                CookieSession::signed(&[0; 32])
                    .domain("mal.camcope.me")
                    .name("mal")
                    .secure(false),
            )
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/logout", web::get().to(logout))
            .route("/auth", web::get().to(auth))
            .route("/mylist", web::get().to(mylist))
            .route("/updatelist", web::get().to(update_list))
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
        Ok(Some(x)) => x,
        _ => false,
    };
    let link: &str = if logged_in { "logout" } else { "login" };

    match session.get::<String>("anonId") {
        Ok(Some(_)) => (),
        _ => session.insert("anonId", "1234abc").unwrap_or(()),
    }

    let mut logged_in_content: Vec<String> = Vec::new();
    if logged_in {
        let token = session
            .get::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>("token")
            .unwrap_or(None);
        if let Some(_) = token {
            logged_in_content.push(r#"<p><a href="/mylist">Anime List</a>"#.to_string());
            logged_in_content.push(r#"<p><a href="/updatelist">Update List</a>"#.to_string());
        };
    };
    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            <a href="/{0}">{0}</a>
            <p>
            {1}
        </body>
    </html>"#,
        link,
        logged_in_content.join("\n<p>\n")
    );

    Ok(HttpResponse::Ok()
        .insert_header(ContentType(TEXT_HTML_UTF_8))
        .body(html))
}

#[instrument(skip(session))]
async fn get_live_token(
    session: Session,
    data: web::Data<AppState>,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
    let token = session
        .get::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>("token")
        .unwrap_or(None);
    let token_expiry = session
        .get::<DateTime<Utc>>("token_expires")
        .unwrap_or(None);
    match (token, token_expiry) {
        (Some(t), Some(e)) => {
            if Utc::now() < e {
                return Ok(t);
            } else {
                return refresh_token(&t, data, &session).await;
            }
        }
        (Some(t), None) => return refresh_token(&t, data, &session).await,
        _ => return Err(error::ErrorNetworkAuthenticationRequired("no valid token")),
    };
}

#[instrument(skip(session))]
async fn refresh_token(
    token: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    data: web::Data<AppState>,
    session: &Session,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
    let refresh = token
        .refresh_token()
        .ok_or_else(|| error::ErrorBadRequest("no refresh token"))?;
    let new_token = data
        .oauth_client
        .exchange_refresh_token(refresh)
        .request_async(async_http_client)
        .await
        .map_err(|e| error::ErrorBadRequest(e.to_string()))?;
    let expiry: DateTime<Utc> = Utc::now()
        + Duration::from_std(
            new_token
                .expires_in()
                .ok_or_else(|| error::ErrorInternalServerError("no token expiry"))?,
        )
        .map_err(|e| error::ErrorInternalServerError(e))?;
    session.insert("token", new_token.clone())?;
    session.insert("token_expires", expiry)?;
    Ok(new_token)
}

#[instrument(skip(session))]
async fn login(session: Session, data: web::Data<AppState>) -> impl Responder {
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    // Generate a PKCE challenge.
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_plain();
    // TODO HAX HAX HAX XXX Uses "plain" pkce challenge type, where it just resends the original
    // code. Switch to sha256 when MAL supports it
    session.insert("PKCE", pkce_challenge.as_str()).unwrap();
    event!(
        Level::DEBUG,
        "\n\nPKCE verifier is {}\n",
        session.get::<String>("PKCE").unwrap().unwrap()
    );

    // Generate the full auth URL to which we'll redirect the user.
    let (auth_url, csrf_token) = &data
        .oauth_client
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

    let verifier = session
        .get::<PkceCodeVerifier>("PKCE")?
        .ok_or_else(|| error::ErrorBadRequest("No PKCE verifier found"))?;
    let token_req = data
        .oauth_client
        .exchange_code(code)
        .set_pkce_verifier(verifier);

    let token = token_req
        .request_async(async_http_client)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

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
    let expiry: DateTime<Utc> = Utc::now()
        + Duration::from_std(
            token
                .expires_in()
                .ok_or_else(|| error::ErrorInternalServerError("no token expiry"))?,
        )
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    session.insert("token", token.clone()).unwrap();
    session.insert("token_expires", expiry).unwrap();
    event!(Level::INFO, "token cookie set");
    session.insert("login", true).unwrap();
    Ok(HttpResponse::Ok().body(html))
}

#[instrument(skip(session))]
async fn mylist(
    session: Session,
    data: web::Data<AppState>,
) -> Result<actix_web::HttpResponse, Error> {
    event!(Level::INFO, "entered mylist route");
    let anime: Vec<AnimeListEntry> =
        serde_json::from_reader(&File::open("./data/animelist.json")?)
            .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;

    let table_columns = ["".to_string(), "Title".to_string(), "Rating".to_string()].join("</th><th>");
    let mut anime_table_contents = String::with_capacity(1048576);
    for a in anime.iter() {
        match a.my_list_status.as_ref()
            .and_then(|l| Some(&l.status))
            .unwrap_or(&UserWatchStatus::Other("None".to_string())) {
            UserWatchStatus::Completed => (),
            UserWatchStatus::Watching => (),
            _ => continue,
        };
        let title: String = if a.english_title.as_ref().and_then(|t| Some(t.contains(&a.title))).unwrap_or(false) {
            a.english_title.clone().unwrap()
        } else if a.english_title.as_ref().unwrap_or(&"".to_string()).len() > 0 {
            format!("{} ({})", (a.english_title.as_ref().unwrap()), (&a.title).clone())
        } else {
            a.title.clone()
        };
        let rating: String = match &a.my_list_status {
            Some(s) => if s.score > 0 { format!("{}", s.score.clone()) } else { "".to_string() },
            _ => "".to_string(),
        };
        anime_table_contents.push_str("<tr><td>");
        let pic: String = match &a.main_picture.medium {
           Some(s) => format!("<img src=\"{}\"", s.clone()),
           _ => "".to_string(),
        };
        let row = vec![
            pic,
            title,
            rating,
        ];
        let row_s: String = row.join("</td><td>").into();
        anime_table_contents.push_str(&row_s);
        anime_table_contents.push_str("</td></tr>");
    }
    let html = format!(
        r#"<html>
        <head>
        <title>Cam's Anime List</title>
        <script src="static/sorttable.js"></script>
        </head>
        <body>
            <p>
            <table class="sortable">
            <thead>
              <tr><th>{}</th></tr>
            </thead>
            <tbody>
            {}
            </tbody>
            </table>
        </body>
    </html>"#,
        table_columns,
        anime_table_contents,
    );
    Ok(HttpResponse::Ok()
        .insert_header(ContentType(TEXT_HTML_UTF_8))
        .body(html))
}

async fn update_list(
    session: Session,
    data: web::Data<AppState>,
) -> Result<web::Json<Vec<AnimeListEntry>>, Error> {
    let token = get_live_token(session, data).await?;
    let client = reqwest::Client::new();
    let res = client
        .get(&(MAL_API.to_string() + "/users/@me/animelist"))
        .query(&[
            ("limit", "1000"),
            ("fields", "id,title,my_list_status"),
            ("nsfw", "true"),
        ])
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| {
            error!("fetch failed, {}", &e);
            error::ErrorInternalServerError(e.to_string())
        })?;
    event!(Level::DEBUG, "my list response\n{:?}", &res);
    if res.status() != 200 {
        return Err(error::ErrorInternalServerError(format!("{:?}", res)));
    }
    event!(Level::INFO, "successful MAL fetch");
    let res_obj: MyAnimeListResponse = res
        .json()
        .await
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    let mut anime: Vec<AnimeListEntry> = res_obj.data.into_iter().map(|x| x.node).collect();
    let lim = RateLimiter::direct(Quota::per_second(nonzero!(2u32)));
    for a in anime.iter_mut() {
        lim.until_ready().await;
        let res = client
            .get(&(MAL_API.to_string() + "/anime/" + &a.id.to_string()))
            .query(&[("fields", "alternative_titles")])
            .bearer_auth(token.access_token().secret())
            .send()
            .await
            .map_err(|e| {
                error!("fetch failed, {}", &e);
                error::ErrorInternalServerError(e.to_string())
            })?;
        event!(Level::DEBUG, "title response\n{:?}", &res);
        if res.status() != 200 {
            return Err(error::ErrorInternalServerError(format!("{:?}", res)));
        }
        let res_obj: MALAltTitleResponse = res
            .json()
            .await
            .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
        a.english_title = res_obj.alternative_titles.en;
    }
    serde_json::to_writer(&File::create("./data/animelist.json")?, &anime)
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    Ok(web::Json(anime))
}
