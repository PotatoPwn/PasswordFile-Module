use std::slice;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use zeroize::Zeroize;
use zxcvbn::{zxcvbn, Score::Three};

pub fn convert_unicode_to_string(unicode_string: &UNICODE_STRING) -> String {
    let buffer =
        unsafe { slice::from_raw_parts(unicode_string.Buffer, unicode_string.Length as usize) };

    let result = String::from_utf16(&buffer);

    return match result {
        Ok(_) => result.unwrap(),
        Err(_) => String::from(""),
    };
}

#[no_mangle]
pub extern "C" fn PasswordFilter(
    account_name: UNICODE_STRING,
    account_full_name: UNICODE_STRING,
    password: UNICODE_STRING,
    set_operation: bool,
) -> bool {
    // Ensure Content isnt Empty :)
    if account_name.Length == 0 || account_full_name.Length == 0 || password.Length == 0 {
        println!("Invalid Parameters");
        return false;
    }

    // Requesting a Password Change
    if !set_operation {
        return false;
    }

    // Convert Unicode Values into String for Easier Handling
    let mut account_name_string = convert_unicode_to_string(&account_full_name);
    let mut password_string = convert_unicode_to_string(&password);

    // Ensure Converted Strings Arent Empty
    if account_name_string.is_empty() || password_string.is_empty() {
        return false;
    }

    // Debugging Purpose
    // println!(
    //     "Account name > {}, Length {}",
    //     account_name_string,
    //     account_name_string.len()
    // );
    //
    // println!(
    //     "Password String > {}, Length {}",
    //     password_string,
    //     password_string.len()
    // );

    // Ensure the Account Name isnt Container inside the Password
    if account_name_string.contains(&password_string) {
        println!("Password Contains Username");

        // Zero out the Sensitive Account Name & String
        account_name_string.zeroize();
        password_string.zeroize();

        return false;
    }

    // Run ZXCVBN Check
    let strength_estimate = zxcvbn(password_string.as_str(), &[account_name_string.as_str()]);

    // Zero out String, Not Needed anymore
    account_name_string.zeroize();
    password_string.zeroize();

    println!("Score > {}", strength_estimate.score());

    if strength_estimate.score() < Three {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rng, seq::IndexedRandom};
    use windows_sys::core::PWSTR;

    fn string_to_unicode(string_value: String) -> UNICODE_STRING {
        let buffer: Vec<u16> = string_value.encode_utf16().collect();

        UNICODE_STRING {
            Buffer: buffer.as_ptr() as PWSTR,
            Length: string_value.len() as u16,
            MaximumLength: string_value.len() as u16,
        }
    }

    #[test]
    fn internal() {
        let username_array = [
            "auditorshut",
            "sheepvine",
            "apatheticsubaltern",
            "netheriteweighty",
            "exposeoften",
            "jumptogs",
            "snortgrist",
            "wildernessbastion",
            "napeve",
            "sleddingbedstraw",
            "ultrasamosa",
            "frankincenselevitate",
        ];

        let password_array = [
            "123456",
            "password",
            "qwerty",
            "111111",
            "12345",
            "baconfa",
            "tes5123",
            "G4$9k2qP!z@8",
            "napeve",
            "sleddingbedstraw",
            "ultrasamosa",
            "frankincenselevitate",
            "S9*j3@tVm4W9",
            "Recreate-Visible-Alarm",
            "Bobcat-Penholder",
            "Overeater",
            "Fervor25",
            "Stabiilize5-Over",
        ];

        for _n in 1..20 {
            let username = string_to_unicode(
                username_array
                    .choose(&mut rng())
                    .cloned()
                    .unwrap()
                    .to_string(),
            );

            let full_name = string_to_unicode(
                username_array
                    .choose(&mut rng())
                    .cloned()
                    .unwrap()
                    .to_string(),
            );

            let password = string_to_unicode(
                password_array
                    .choose(&mut rng())
                    .cloned()
                    .unwrap()
                    .to_string(),
            );

            if PasswordFilter(username, full_name, password, true) {
                println!("Passed!")
            } else {
                println!("Failed!")
            }

            println!("=================================================\n")
        }
    }
}
