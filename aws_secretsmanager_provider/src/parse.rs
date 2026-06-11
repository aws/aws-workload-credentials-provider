use std::borrow::Borrow;
use std::sync::OnceLock;

use regex::Regex;
use url::Url;

use crate::error::HttpError;

#[derive(Debug)]
pub(crate) struct GSVQuery {
    pub secret_id: String,
    pub version_id: Option<String>,
    pub version_stage: Option<String>,
    pub refresh_now: bool,
    pub role_arn: Option<String>,
}

impl GSVQuery {
    fn parse_refresh_value(s: &str) -> Result<bool, HttpError> {
        match s.to_lowercase().as_str() {
            "true" => Ok(true),
            "1" => Ok(true),
            "false" => Ok(false),
            "0" => Ok(false),
            _ => Err(HttpError(400, "invalid refreshNow value".to_string())),
        }
    }

    /// Validate the role ARN against a strict IAM role ARN format.
    ///
    /// Checks that the provided string matches the IAM role ARN pattern
    /// `arn:<partition>:iam::<account>:role/<name>`
    ///
    /// # Arguments
    ///
    /// * `arn` - The role ARN string to validate.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the ARN passes format validation.
    ///
    /// # Errors
    ///
    /// * `HttpError(400, ...)` - If the ARN does not match the expected format.
    fn validate_role_arn(arn: &str) -> Result<(), HttpError> {
        static ROLE_ARN_RE: OnceLock<Regex> = OnceLock::new();
        let re = ROLE_ARN_RE.get_or_init(|| {
            Regex::new(r"^arn:[\w-]+:iam::\d{12}:role/[\w+=,.@/-]+$")
                .expect("hard-coded roleArn regex must compile")
        });
        if !re.is_match(arn) {
            return Err(HttpError(
                400,
                "invalid roleArn format, expected arn:<partition>:iam::<account>:role/<name>"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn try_from_query(s: &str) -> Result<Self, HttpError> {
        // url library can only parse complete URIs. The host/port/scheme used is irrelevant since it is not used
        let complete_uri = format!("http://localhost{}", s);

        let url = Url::parse(&complete_uri)?;

        let mut query = GSVQuery {
            secret_id: "".into(),
            version_id: None,
            version_stage: None,
            refresh_now: false,
            role_arn: None,
        };

        for (k, v) in url.query_pairs() {
            match k.borrow() {
                "secretId" => query.secret_id = v.into(),
                "versionId" => query.version_id = Some(v.into()),
                "versionStage" => query.version_stage = Some(v.into()),
                "refreshNow" => query.refresh_now = GSVQuery::parse_refresh_value(&v)?,
                "roleArn" => query.role_arn = Some(v.into()),
                p => return Err(HttpError(400, format!("unknown parameter: {}", p))),
            }
        }

        if query.secret_id.is_empty() {
            return Err(HttpError(400, "missing parameter secretId".to_string()));
        }

        if let Some(ref arn) = query.role_arn {
            Self::validate_role_arn(arn)?;
        }

        Ok(query)
    }

    pub(crate) fn try_from_path_query(s: &str, path_prefix: &str) -> Result<Self, HttpError> {
        // url library can only parse complete URIs. The host/port/scheme used is irrelevant since it gets stripped
        let complete_uri = format!("http://localhost{}", s);

        let url = Url::parse(&complete_uri)?;

        let secret_id = match url.path().get(path_prefix.len()..) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Err(HttpError(400, "missing secret ID".to_string())),
        };

        let mut query = GSVQuery {
            secret_id,
            version_id: None,
            version_stage: None,
            refresh_now: false,
            role_arn: None,
        };

        for (k, v) in url.query_pairs() {
            match k.borrow() {
                "versionId" => query.version_id = Some(v.into()),
                "versionStage" => query.version_stage = Some(v.into()),
                "refreshNow" => query.refresh_now = GSVQuery::parse_refresh_value(&v)?,
                "roleArn" => query.role_arn = Some(v.into()),
                p => return Err(HttpError(400, format!("unknown parameter: {}", p))),
            }
        }

        if let Some(ref arn) = query.role_arn {
            Self::validate_role_arn(arn)?;
        }

        Ok(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query() {
        let secret_id = "MyTest".to_owned();
        let query =
            GSVQuery::try_from_query(&format!("/secretsmanager/get?secretId={}", secret_id))
                .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert_eq!(query.refresh_now, false);
    }

    #[test]
    fn parse_query_refresh() {
        let secret_id = "MyTest".to_owned();
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&refreshNow={}",
            secret_id, true
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert_eq!(query.refresh_now, true);
    }

    #[test]
    fn parse_query_refresh_false() {
        let secret_id = "MyTest".to_owned();
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&refreshNow={}",
            secret_id, "0"
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert_eq!(query.refresh_now, false);
    }

    #[test]
    fn parse_refresh_invalid_parameter() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&versionId={}&versionStage={}&refreshNow=123",
            secret_id, version_id, version_stage
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "invalid refreshNow value");
            }
        }
    }

    #[test]
    fn parse_refresh_case_insensitive() {
        let secret_id = "MyTest".to_owned();
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&refreshNow={}",
            secret_id, "FALSE"
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert_eq!(query.refresh_now, false);
    }

    #[test]
    fn parse_path_query() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        let path_prefix = "/v1/";

        let query = GSVQuery::try_from_path_query(
            &format!(
                "{}{}?versionId={}&versionStage={}",
                path_prefix, secret_id, version_id, version_stage
            ),
            path_prefix,
        )
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, Some(version_id));
        assert_eq!(query.version_stage, Some(version_stage));
    }

    #[test]
    fn parse_query_invalid_parameter() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&versionId={}&versionStage={}&abc=123",
            secret_id, version_id, version_stage
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "unknown parameter: abc");
            }
        }
    }

    #[test]
    fn parse_query_path_invalid_parameter() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        let path_prefix = "/v1/";

        match GSVQuery::try_from_path_query(
            &format!(
                "{}{}?versionId={}&versionStage={}&abc=123",
                path_prefix, secret_id, version_id, version_stage
            ),
            path_prefix,
        ) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "unknown parameter: abc");
            }
        }
    }

    #[test]
    fn parse_query_with_role_arn() {
        let secret_id = "arn:aws:secretsmanager:us-east-1:987654321098:secret:MySecret-AbCdEf";
        let role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole";
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&roleArn={}",
            secret_id, role_arn
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.role_arn, Some(role_arn.to_string()));
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert_eq!(query.refresh_now, false);
    }

    #[test]
    fn parse_query_without_role_arn() {
        let secret_id = "MyTest".to_owned();
        let query =
            GSVQuery::try_from_query(&format!("/secretsmanager/get?secretId={}", secret_id))
                .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.role_arn, None);
    }

    #[test]
    fn parse_query_all_params_with_role_arn() {
        let secret_id = "arn:aws:secretsmanager:us-east-1:987654321098:secret:MySecret-AbCdEf";
        let version_id = "myversion";
        let version_stage = "AWSPENDING";
        let role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole";
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&versionId={}&versionStage={}&refreshNow=true&roleArn={}",
            secret_id, version_id, version_stage, role_arn
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, Some(version_id.to_string()));
        assert_eq!(query.version_stage, Some(version_stage.to_string()));
        assert_eq!(query.refresh_now, true);
        assert_eq!(query.role_arn, Some(role_arn.to_string()));
    }

    #[test]
    fn parse_path_query_with_role_arn() {
        let secret_id = "arn:aws:secretsmanager:us-east-1:987654321098:secret:MySecret-AbCdEf";
        let role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole";
        let path_prefix = "/v1/";

        let query = GSVQuery::try_from_path_query(
            &format!("{}{}?roleArn={}", path_prefix, secret_id, role_arn),
            path_prefix,
        )
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.role_arn, Some(role_arn.to_string()));
    }

    #[test]
    fn parse_path_query_without_role_arn() {
        let secret_id = "MyTest".to_owned();
        let path_prefix = "/v1/";

        let query =
            GSVQuery::try_from_path_query(&format!("{}{}", path_prefix, secret_id), path_prefix)
                .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.role_arn, None);
    }

    #[test]
    fn parse_query_missing_secret_id() {
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?&versionId={}&versionStage={}",
            version_id, version_stage
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "missing parameter secretId");
            }
        }
    }

    #[test]
    fn parse_query_invalid_role_arn() {
        let secret_id = "MyTest";
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&roleArn=notAnArn",
            secret_id
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert!(e.1.contains("invalid roleArn format"));
            }
        }
    }

    #[test]
    fn parse_query_invalid_role_arn_missing_role() {
        let secret_id = "MyTest";
        // Has iam but no :role/ segment
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&roleArn=arn:aws:iam::123456789012:user/SomeUser",
            secret_id
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert!(e.1.contains("invalid roleArn format"));
            }
        }
    }

    #[test]
    fn parse_path_query_invalid_role_arn() {
        let secret_id = "MyTest";
        let path_prefix = "/v1/";
        match GSVQuery::try_from_path_query(
            &format!("{}{}?roleArn=garbage", path_prefix, secret_id),
            path_prefix,
        ) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert!(e.1.contains("invalid roleArn format"));
            }
        }
    }

    #[test]
    fn parse_query_path_missing_secret_id() {
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        let path_prefix = "/v1/";

        match GSVQuery::try_from_path_query(
            &format!(
                "{}?versionId={}&versionStage={}&abc=123",
                path_prefix, version_id, version_stage
            ),
            path_prefix,
        ) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "missing secret ID");
            }
        }
    }

    fn parse_with_role_arn(raw_role_arn: &str) -> Result<GSVQuery, HttpError> {
        let query = format!(
            "/secretsmanager/get?secretId=random-secret&roleArn={}",
            raw_role_arn
        );
        GSVQuery::try_from_query(&query)
    }

    #[test]
    fn reject_role_arn_with_injected_json_fields() {
        let payload = "arn:aws:iam::987654321098:role/test\",\"injected\":\"value";
        let err = parse_with_role_arn(payload).expect_err("must reject JSON injection");
        assert_eq!(err.0, 400);
        assert!(err.1.contains("invalid roleArn format"));
    }

    #[test]
    fn reject_role_arn_with_backslash_quote() {
        let payload = "arn:aws:iam::987654321098:role/test\\\"injected";
        let err = parse_with_role_arn(payload).expect_err("must reject backslash-quote");
        assert_eq!(err.0, 400);
        assert!(err.1.contains("invalid roleArn format"));
    }

    #[test]
    fn reject_role_arn_with_wrong_account() {
        for payload in &[
            "arn:aws:iam::12345:role/Admin",
            "arn:aws:iam::1234567890123:role/Admin",
            "arn:aws:iam::12345678901a:role/Admin",
            "arn:aws:iam:::role/Admin",
        ] {
            let err = parse_with_role_arn(payload).expect_err("must reject bad account");
            assert_eq!(err.0, 400);
        }
    }

    #[test]
    fn reject_role_arn_with_empty_name() {
        let err = parse_with_role_arn("arn:aws:iam::123456789012:role/")
            .expect_err("must reject empty role name");
        assert_eq!(err.0, 400);
    }

    #[test]
    fn reject_role_arn_with_wrong_service() {
        for payload in &[
            "arn:aws:s3:::123456789012:role/Admin",
            "arn:aws:iam:us-east-1:123456789012:role/Admin",
            "arn:aws:sts::123456789012:role/Admin",
        ] {
            let err = parse_with_role_arn(payload).expect_err("must reject bad service");
            assert_eq!(err.0, 400);
        }
    }

    #[test]
    fn accept_role_arn_with_path() {
        for payload in &[
            "arn:aws:iam::123456789012:role/service-role/MyRole",
            "arn:aws:iam::123456789012:role/path/to/nested/Role_Name-1",
        ] {
            parse_with_role_arn(payload)
                .unwrap_or_else(|e| panic!("valid role name must parse ({payload:?}): {e:?}"));
        }
    }
}
