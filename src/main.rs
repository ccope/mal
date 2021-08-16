use actix_files::Files;
use actix_session::{CookieSession, Session};
use actix_web::http::header;
use actix_web::http::header::ContentType;
use actix_web::{error, web, App, Error, HttpResponse, HttpServer, Responder, Result};
use chrono::prelude::*;
use chrono::Duration;
use dotenv::dotenv;
use gestalt_ratio::gestalt_ratio;
use mime::TEXT_HTML_UTF_8;
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
    RedirectUrl,
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

const DOMAIN: &str = "mal.camcope.me";
const PORT: u32 = 9090;
const MAL_API: &str = "https://api.myanimelist.net/v2";
const MAL_WEB: &str = "https://www.myanimelist.net";

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
    let port: u32 = match env::var("PORT".to_string()) {
        Ok(p) => p.parse().unwrap_or(PORT),
        _ => PORT,
    };
    let client_id = ClientId::new(env::var("CLIENT_ID".to_string())?);
    let client_secret = Some(ClientSecret::new(env::var("CLIENT_SECRET")?));
    let auth_url = AuthUrl::new(env::var("AUTH_URL")?)?;
    let token_url = Some(TokenUrl::new(env::var("TOKEN_URL")?)?);
    let redirect_url = RedirectUrl::new(env::var("REDIRECT_URL")?)?;

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = Box::new(
        BasicClient::new(client_id, client_secret, auth_url, token_url)
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(redirect_url)
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                oauth_client: client.clone()
            }))
            .service(
                Files::new("/static", "./static")
                    .prefer_utf8(true)
                    .use_etag(true),
            )
            .wrap(
                CookieSession::signed(&[0; 32])
                    .domain(DOMAIN)
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
    .bind(format!("127.0.0.1:{}", port))
    .unwrap_or_else(|_| panic!("Can not bind to port {}", port))
    .run()
    .await?;
    Ok(())
}


fn linkify(text: &str, link: &str) -> String {
    format!("<a href=\"{}\">{}</a>", link, text)
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
        if let Some(t) = token {
            logged_in_content.push(r#"<p><a href="/mylist">Anime List</a>"#.to_string());
            logged_in_content.push(r#"<p><a href="/updatelist">Update List</a>"#.to_string());
            if std::env::var("RUST_LOG") == Ok("DEBUG".to_string()) {
                logged_in_content.push(format!("<p>TOKEN IS {:?}", t.access_token().secret()));
            }
        };
    };
    let html = format!(
        r#"<html>
        <head>
          <title>MyMAL</title>
          <link rel="stylesheet" href="static/main.css">
        </head>
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
        .map_err(error::ErrorInternalServerError)?;
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

    event!(Level::DEBUG, "\n\nCSRF token is {}", csrf_token.secret());
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
        .map_err(error::ErrorInternalServerError)?;

    event!(Level::DEBUG, "token {:?}", &token);

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
    match env::var("RUST_LOG".to_string()).unwrap_or_else(|_| "".to_string()).as_str() {
        "DEBUG" => {
            let html = format!(
                r#"<html>
                <head>
                  <title>OAuth2 Test</title>
                  <link rel="stylesheet" href="static/main.css">
                </head>
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
            return Ok(HttpResponse::Ok().insert_header(ContentType(TEXT_HTML_UTF_8)).body(html))
        },
        _ => Ok(HttpResponse::Found()
            .append_header((header::LOCATION, format!("https://{}", DOMAIN)))
            .finish()
        )

    }
}

fn are_titles_similar(title1: &str, title2: &str) -> bool {
    gestalt_ratio(
        &title1.replace("Season", "").to_lowercase(),
        &title2.replace("Season", "").to_lowercase()
        ) > 0.7
}

fn select_best_title(anime: &AnimeListEntry) -> String {
    let en_title_contains_default = anime.alternative_titles.en.as_ref()
        .map(|t| t.to_lowercase().contains(&anime.title.to_lowercase()))
        .unwrap_or(false);
    let en_title_is_similar_to_default = anime.alternative_titles.en.as_ref()
        .map(|t| are_titles_similar(t, &anime.title))
        .unwrap_or(false);

    if en_title_contains_default || en_title_is_similar_to_default {
        anime.alternative_titles.en.clone().unwrap()
    } else if !anime.alternative_titles.en.as_ref().unwrap_or(&"".to_string()).is_empty() {
        format!("{}<br />({})", (anime.alternative_titles.en.as_ref().unwrap()), (&anime.title).clone())
    } else if anime.alternative_titles.synonyms.as_ref()
        .and_then(|s| if s.len() > 0 { Some(s) } else { None })
        .and_then(|s| Some(are_titles_similar(&s[0], &anime.title)))
        .unwrap_or(false) {
            // TODO HACK: check if any synonyms are similar, not just the first
        format!("{}<br />({})", (anime.alternative_titles.synonyms.as_ref().unwrap()[0].clone()), (&anime.title).clone())
    } else {
        anime.title.clone()
    }
}

fn make_anime_row(anime: &AnimeListEntry) -> String {
    let title: String = select_best_title(anime);
    let title_with_link = linkify(&title, format!("{}/anime/{}", &MAL_WEB, &anime.id).as_ref());
    let genres = anime.genres.iter().map(|g: &MALGenre| g.name.clone()).collect::<Vec<String>>().join(", ");
    let tags = match &anime.my_list_status.as_ref().and_then(|l| l.tags.as_ref()) {
        Some(t) => t.join(", "),
        _ => "".to_string(),
    };
    let rating: String = match &anime.my_list_status {
        Some(s) => {
            if s.score > 0 {
                format!("{}", s.score.clone())
            } else {
                "".to_string()
            }
        }
        _ => "".to_string(),
    };
    let pic: String = match &anime.main_picture.medium {
        Some(s) => format!(r#"<img src="{}">"#, s.clone()),
        _ => "".to_string(),
    };
    let pic_with_link = linkify(&pic, format!("{}/anime/{}", &MAL_WEB, &anime.id).as_ref());
    let row = vec![
        pic_with_link,
        title_with_link,
        genres,
        tags,
        rating,
        anime.start_date
            .map(|d| d.to_string())
            .unwrap_or_else(|| "".to_string()),
    ];
    format!("<tr><td>{}</td></tr>", row.join("</td><td>"))
}

fn append_column(columns: &mut Vec<String>, column: String, tag: Option<String>) {
    match tag {
        Some(t) => columns.push(format!("<th {}>{}</th>", t, column)),
        None => columns.push(format!("<th>{}</th>", column)),
    }
}

async fn mylist() -> Result<actix_web::HttpResponse, Error> {
    event!(Level::INFO, "entered mylist route");
    let anime: Vec<AnimeListEntry> = serde_json::from_reader(&File::open("./data/animelist.json")?)
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;

    let mut table_columns: Vec<String> = Vec::new();
    append_column(&mut table_columns, "".to_string(), None);
    append_column(&mut table_columns, "Title".to_string(), Some("class=\"sorttable_alpha\"".to_string()));
    append_column(&mut table_columns, "Genres".to_string(), None);
    append_column(&mut table_columns, "Tags".to_string(), None);
    append_column(&mut table_columns, "Rating".to_string(), None);
    append_column(&mut table_columns, "Aired".to_string(), None);

    let mut anime_table_contents = String::with_capacity(1048576);
    for a in anime.iter() {
        match a.my_list_status.as_ref()
        // Only show watched or watching shows
        // TODO: Make this filterable in the UI
            .map(|l| &l.status)
            .unwrap_or(&UserWatchStatus::Other("None".to_string())) {
            UserWatchStatus::Completed => (),
            UserWatchStatus::Watching => (),
            _ => continue,
        };
        let row_s = make_anime_row(a);
        anime_table_contents.push_str(&row_s);
    }
    let html = format!(
        r#"<html>
        <head>
          <title>Cam's Anime List</title>
          <link rel="stylesheet" href="static/main.css">
          <script src="static/sorttable.js"></script>
        </head>
        <body>
            <p>
            <table class="sortable">
            <thead>
              <tr>{}</tr>
            </thead>
            <tbody>
            {}
            </tbody>
            </table>
        </body>
    </html>"#,
        table_columns.join("\n"), anime_table_contents,
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
            ("fields", "id,title,alternative_titles,genres,media_type,num_episodes,synopsis,my_list_status{status,score,start_date,tags,updated_at},start_date"),
            //("nsfw", "true"),
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
    let res_text: String = res
        .text()
        .await
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    event!(Level::DEBUG, "raw result:\n{:#?}", &res_text);
    let anime: Vec<AnimeListEntry> = serde_json::from_str(&res_text)
        .map(|r: MyAnimeListResponse| r.data.into_iter().map(|x| x.node).collect())
        .map_err(|e| {
            error!("fetch failed, {}", &e);
            error::ErrorInternalServerError(web::Json(res_text))
        })?;
    serde_json::to_writer(&File::create("./data/animelist.json")?, &anime)
        .map_err(|e| error::ErrorInternalServerError(e.to_string()))?;
    Ok(web::Json(anime))
}
