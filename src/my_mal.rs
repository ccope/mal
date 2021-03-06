use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use std::str::FromStr;
use strum_macros::{EnumString, IntoStaticStr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnimeListEntryPictures {
    pub small: Option<String>,
    pub medium: Option<String>,
    pub large: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MALGenre {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnimeListEntry {
    pub id: i64,
    pub title: String,
    pub alternative_titles: MALTitleTypes,
    pub genres: Vec<MALGenre>,
    pub media_type: String,
    pub num_episodes: u16,
    pub synopsis: String,
    pub main_picture: AnimeListEntryPictures,
    pub my_list_status: Option<UserAnimeListStatus>,
    pub start_date: Option<NaiveDate>,
}

#[derive(Clone, Debug, PartialEq, EnumString, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum UserWatchStatus {
    Watching,
    Completed,
    OnHold,
    Dropped,
    PlanToWatch,
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserAnimeListStatus {
    pub status: UserWatchStatus,
    pub score: u8,
    pub num_episodes_watched: Option<u64>,
    pub is_rewatching: Option<bool>,
    pub start_date: Option<NaiveDate>,
    pub finish_date: Option<NaiveDate>,
    pub priority: Option<u8>,
    pub num_times_rewatched: Option<u64>,
    pub rewatch_value: Option<u8>,
    pub tags: Option<Vec<String>>,
    pub comments: Option<String>,
    pub updated_at: DateTime<Utc>,
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
pub struct AnimeDetailResponse {
    pub alternative_titles: MALTitleTypes,
    pub start_date: Option<NaiveDate>,
}

impl Serialize for UserWatchStatus {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.into())
    }
}
impl<'de> Deserialize<'de> for UserWatchStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match Self::from_str(s.as_str()) {
            Ok(n) => Ok(n),
            Err(_) => Ok(Self::Other(s)),
        }
    }
    fn deserialize_in_place<D>(
        deserializer: D,
        place: &mut Self,
    ) -> Result<(), <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        *place = match Self::from_str(s.as_str()) {
            Ok(n) => n,
            Err(_) => Self::Other(s),
        };
        Ok(())
    }
}
