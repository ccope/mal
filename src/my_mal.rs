use serde::{Deserialize, Serialize};

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
    pub english_title: Option<String>,
    pub main_picture: AnimeListEntryPictures,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct MALTitleTypes {
    pub synonyms: Option<Vec<String>>,
    pub en: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MALAltTitleResponse {
    pub alternative_titles: MALTitleTypes,
}
