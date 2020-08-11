use anyhow::Result;
use dotenv::dotenv;
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    TokenResponse,
    TokenUrl
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use std::env;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client =
        BasicClient::new(
            ClientId::new(env::var("CLIENT_ID".to_string())?),
            Some(ClientSecret::new(env::var("CLIENT_SECRET".to_string())?)),
            AuthUrl::new(env::var("AUTH_URL".to_string())?)?,
            Some(TokenUrl::new("http://token".to_string())?)
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_url(RedirectUrl::new("http://redirect".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("read".to_string()))
        //.add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    // Unwrapping token_result will either produce a Token or a RequestTokenError.

    println!("Hello, world!");
    println!("{:?}", token_result);
    Ok(())
}

async fn start_auth() -> Result<String, anyhow::Error> {
    Ok("".to_string())
}

async fn finish_auth(token: String) -> Result<()> {
    unimplemented!();
    Ok(())
}
