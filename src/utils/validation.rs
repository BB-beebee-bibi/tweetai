use crate::error::Error;

// Validate theme selection
pub fn validate_theme(theme: &str) -> Result<(), Error> {
    let valid_themes = ["Agora", "Sky", "Castle", "Mountaintop", "Wild Card"];
    
    if !valid_themes.contains(&theme) {
        return Err(Error::BadRequest(format!(
            "Invalid theme selection. Valid options are: {}",
            valid_themes.join(", ")
        )));
    }
    
    Ok(())
}

// Validate message content
pub fn validate_message_content(content: &str) -> Result<(), Error> {
    if content.is_empty() {
        return Err(Error::BadRequest("Message content cannot be empty".into()));
    }
    
    if content.chars().count() > 256 {
        return Err(Error::BadRequest("Message exceeds 256 character limit".into()));
    }
    
    Ok(())
}

// Validate user state fields
pub fn validate_user_state(
    sleep_status: Option<&str>,
    workday_status: Option<&str>,
    calories: Option<i32>,
) -> Result<(), Error> {
    // Validate sleep status if provided
    if let Some(status) = sleep_status {
        let valid_sleep_statuses = ["asleep", "awake", "napping", "unknown"];
        if !valid_sleep_statuses.contains(&status) {
            return Err(Error::BadRequest(format!(
                "Invalid sleep status. Valid options are: {}",
                valid_sleep_statuses.join(", ")
            )));
        }
    }
    
    // Validate workday status if provided
    if let Some(status) = workday_status {
        let valid_workday_statuses = ["working", "off", "meeting", "break", "unknown"];
        if !valid_workday_statuses.contains(&status) {
            return Err(Error::BadRequest(format!(
                "Invalid workday status. Valid options are: {}",
                valid_workday_statuses.join(", ")
            )));
        }
    }
    
    // Validate calories if provided
    if let Some(cal) = calories {
        if cal < 0 || cal > 10000 {
            return Err(Error::BadRequest(
                "Calories must be between 0 and 10000".into()
            ));
        }
    }
    
    Ok(())
}

// Sanitize input to prevent XSS and other injection attacks
pub fn sanitize_input(input: &str) -> String {
    // This is a simple implementation
    // In a production environment, use a proper HTML sanitizer library
    let mut sanitized = input.replace('<', "&lt;");
    sanitized = sanitized.replace('>', "&gt;");
    sanitized = sanitized.replace('&', "&amp;");
    sanitized = sanitized.replace('"', "&quot;");
    sanitized = sanitized.replace('\'', "&#x27;");
    sanitized = sanitized.replace('/', "&#x2F;");
    
    sanitized
}