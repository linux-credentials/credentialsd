#[derive(Debug)]
pub(crate) enum Origin {
    AppId(String),
    SameOrigin(String),
    CrossOrigin((String, String)),
}

impl Origin {
    pub(crate) fn origin(&self) -> &str {
        &match self {
            Origin::AppId(app_id) => app_id,
            Origin::SameOrigin(origin) => origin,
            Origin::CrossOrigin((origin, _)) => origin,
        }
    }

    pub(crate) fn top_origin(&self) -> Option<&str> {
        match self {
            Origin::AppId(_) => None,
            Origin::SameOrigin(_) => None,
            Origin::CrossOrigin((_, ref top_origin)) => Some(top_origin),
        }
    }
}
