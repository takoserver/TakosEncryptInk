use regex::Regex;
/// UUID v7 フォーマットかどうかを検証
pub fn is_valid_uuid_v7(uuid: &str) -> bool {
    let re = Regex::new(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ).unwrap();
    re.is_match(uuid)
}
