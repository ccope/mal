use actix_web::{get, web, App, HttpServer, HttpResponse, Responder};
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
    RedirectUrl,
    Scope,
    TokenResponse,
    TokenUrl
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

const PORT: i32 = 9090;
struct AppState {
    oauth_client: Box<BasicClient>,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let client_id = ClientId::new(env::var("CLIENT_ID".to_string())?);
    let client_secret = Some(ClientSecret::new(env::var("CLIENT_SECRET")?));
    let auth_url = AuthUrl::new(env::var("AUTH_URL")?)?;
    let token_url = Some(TokenUrl::new(env::var("TOKEN_URL")?)?);
    let redirect_url = RedirectUrl::new(env::var("REDIRECT_URL")?)?;

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
        .set_redirect_url(redirect_url)
    );

    HttpServer::new(move || {
        App::new()
            .data(AppState { oauth_client: client.clone() })
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
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

fn index(session: Session) -> HttpResponse {
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

    HttpResponse::Ok().body(html)
}

fn login(data: web::Data<AppState>) -> HttpResponse {
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    // Generate a PKCE challenge.
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full auth URL to which we'll redirect the user.
    let (auth_url, csrf_token) = &data.oauth_client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("read".to_string()))
        //.add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    HttpResponse::Found()
        .header(header::LOCATION, auth_url.to_string())
        .finish()
}

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.


    ///// // Generate a PKCE challenge.
    ///// let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();


    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.


// async fn finish_auth(client: BasicClient, pkce_verifier: PkceCodeVerifier) -> Result<TokenResponse> {
//     // Now you can trade it for an access token.
//     let token_result = client
//         .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
//         // Set the PKCE code verifier.
//         .set_pkce_verifier(pkce_verifier)
//         .request_async(async_http_client)
//         .await?;
// 
//     // Unwrapping token_result will either produce a Token or a RequestTokenError.
// 
//     println!("Hello, world!");
//     println!("{:?}", token_result);
//     Ok(token_result)
// }

fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .header(header::LOCATION, "/".to_string())
        .finish()
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: String,
}

fn auth(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {
    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());
    let _scope = params.scope.clone();

    // Exchange the code with a token.
    let token = &data.oauth_client.exchange_code(code);

    session.set("login", true).unwrap();

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            API returned the following state:
            <pre>{}</pre>
            API returned the following token:
            <pre>{:?}</pre>
        </body>
    </html>"#,
        state.secret(),
        token
    );
    HttpResponse::Ok().body(html)
}
