#[derive(Debug)]
pub(crate) struct HttpError(pub u16, pub String);

impl From<url::ParseError> for HttpError {
    fn from(e: url::ParseError) -> Self {
        HttpError(400, e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error() {
        let error = HttpError::from(url::ParseError::Overflow);
        assert_eq!(400, error.0);
        assert_eq!("URLs more than 4 GB are not supported", error.1);
    }
}
