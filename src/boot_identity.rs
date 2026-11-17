//! What tells two computers apart at network boot: the SMBIOS serial number
//! and the SMBIOS system UUID iPXE reports.
//!
//! The Nest still finds a computer by the MAC address it boots with. A USB
//! Ethernet adapter moved between laptops brings that MAC to every one of
//! them, so a serial number that is real and differs from the one stored for
//! the MAC means another computer is using the adapter. Firmware often
//! reports a placeholder instead of a serial; those never decide anything.
//!
//! Tiaris knows a computer's system UUID only as the hardware fingerprint its
//! agent reports (`sha256("tiaris-hardware-v1\ndmi_product_uuid=<uuid>")`).
//! The Nest hashes the UUID iPXE reports the same way, so Manage can name the
//! computer a reinstall is for, and the computers it knows, by fingerprint.

use sha2::{Digest, Sha256};

const MAX_SERIAL_CHARS: usize = 128;
/// iPXE sends the serial as `${serial:hexraw}`; anything longer than this
/// could never be a usable serial.
const MAX_SERIAL_HEX_CHARS: usize = 1024;

/// Values firmware vendors leave in SMBIOS instead of a real serial number,
/// compared case-insensitively.
const PLACEHOLDER_SERIALS: &[&str] = &[
    "default string",
    "default",
    "to be filled by o.e.m.",
    "oem",
    "system serial number",
    "chassis serial number",
    "base board serial number",
    "serial number",
    "not specified",
    "not applicable",
    "not available",
    "n/a",
    "na",
    "none",
    "unknown",
    "invalid",
    "0123456789",
    "1234567890",
    "123456789",
    "12345678",
];

/// The serial number as stored and compared, or `None` when the value cannot
/// identify a computer: empty, longer than 128 characters, a known
/// placeholder, or one repeated character such as `00000000`.
pub fn usable_serial(value: &str) -> Option<String> {
    let cleaned: String = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_SERIAL_CHARS {
        return None;
    }
    let lowercase = trimmed.to_lowercase();
    if PLACEHOLDER_SERIALS.contains(&lowercase.as_str()) {
        return None;
    }
    let mut alphanumerics = trimmed
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase());
    let first = alphanumerics.next()?;
    if alphanumerics.all(|ch| ch == first) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Two usable serial numbers name the same computer. Case is ignored because
/// an operator may retype a serial in Manage.
pub fn same_serial(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

/// Before boot requests carried the serial, menu links sent it unencoded and
/// iPXE split the command at its first space, so a row may hold only the
/// first word of a serial such as `VMware-56 4d 1a …`. That row still
/// belongs to the computer reporting the full serial.
pub fn stored_by_old_menu_link(stored: &str, incoming: &str) -> bool {
    let mut words = incoming.split_whitespace();
    let first = words.next();
    words.next().is_some() && first.is_some_and(|first| same_serial(first, stored))
}

/// Decode the serial that iPXE expanded with `${serial:hexraw}`: hex keeps
/// every byte URL-safe, where `uristring` leaves `"`, `<` and `>` that the
/// HTTP server rejects before the Nest sees the request.
pub fn serial_from_hex(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_SERIAL_HEX_CHARS
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let bytes = value
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// System UUIDs firmware vendors ship on every unit of a model, so they name
/// no single computer.
const PLACEHOLDER_UUIDS: &[&str] = &[
    "03000200-0400-0500-0006-000700080009",
    "00020003-0004-0005-0006-000700080009",
    "12345678-1234-5678-90ab-cddeefaabbcc",
];

/// The SMBIOS system UUID as the Tiaris agent normalises it (trimmed and
/// lowercase), or `None` when it cannot identify a computer: empty, not hex
/// and dashes, fewer than 12 hex digits, all zeros or all `f`, or a known
/// placeholder. iPXE's `${uuid}` and Linux's `product_uuid` print the same
/// bytes the same way, so both sides hash the same text.
pub fn usable_uuid(value: &str) -> Option<String> {
    let uuid = value.trim().to_ascii_lowercase();
    if uuid.is_empty()
        || uuid.len() > 64
        || !uuid.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
    {
        return None;
    }
    let hex: Vec<char> = uuid.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() < 12
        || hex.iter().all(|ch| *ch == '0')
        || hex.iter().all(|ch| *ch == 'f')
        || PLACEHOLDER_UUIDS.contains(&uuid.as_str())
    {
        return None;
    }
    Some(uuid)
}

/// The hardware fingerprint the Tiaris agent reports for a computer with this
/// (usable) system UUID.
pub fn uuid_fingerprint(uuid: &str) -> String {
    hex::encode(Sha256::digest(
        format!("tiaris-hardware-v1\ndmi_product_uuid={uuid}").as_bytes(),
    ))
}

/// A hardware fingerprint as Manage sends it: 64 lowercase hex digits.
pub fn is_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        is_fingerprint, same_serial, serial_from_hex, stored_by_old_menu_link, usable_serial,
        usable_uuid, uuid_fingerprint,
    };

    #[test]
    fn real_serials_are_usable_and_trimmed() {
        assert_eq!(usable_serial(" 5CG1234XYZ ").as_deref(), Some("5CG1234XYZ"));
        assert_eq!(usable_serial("PF2ABCDE").as_deref(), Some("PF2ABCDE"));
        assert_eq!(usable_serial("0F00-1A").as_deref(), Some("0F00-1A"));
    }

    #[test]
    fn placeholders_are_not_usable_in_any_case() {
        for value in [
            "Default string",
            "To Be Filled By O.E.M.",
            "SYSTEM SERIAL NUMBER",
            "Not Specified",
            "N/A",
            "None",
            "0123456789",
            "OEM",
        ] {
            assert_eq!(usable_serial(value), None, "{value}");
        }
    }

    #[test]
    fn empty_repeated_and_oversized_values_are_not_usable() {
        assert_eq!(usable_serial(""), None);
        assert_eq!(usable_serial(" \t\n "), None);
        assert_eq!(usable_serial("00000000"), None);
        assert_eq!(usable_serial("FFFF-FFFF"), None);
        assert_eq!(usable_serial("xxxxXXXX"), None);
        assert_eq!(usable_serial("----"), None);
        assert_eq!(usable_serial(&"A1".repeat(65)), None);
        assert!(usable_serial(&"A1".repeat(64)).is_some());
    }

    #[test]
    fn control_characters_cannot_hide_a_placeholder() {
        assert_eq!(usable_serial("Default\u{0}string"), None);
        assert_eq!(usable_serial("\u{7}None\u{7}"), None);
    }

    #[test]
    fn hex_serials_decode_every_byte_and_reject_malformed_values() {
        assert_eq!(serial_from_hex("3543473132").as_deref(), Some("5CG12"));
        assert_eq!(
            serial_from_hex("4142223c3e2023").as_deref(),
            Some("AB\"<> #")
        );
        assert_eq!(serial_from_hex(""), None);
        assert_eq!(serial_from_hex("354"), None);
        assert_eq!(serial_from_hex("zz"), None);
        assert_eq!(serial_from_hex("+1"), None);
        assert_eq!(serial_from_hex("\u{e9}a"), None);
        assert_eq!(serial_from_hex(&"41".repeat(513)), None);
    }

    #[test]
    fn a_first_word_stored_by_old_menu_links_matches_the_full_serial() {
        assert!(stored_by_old_menu_link("VMware-56", "VMware-56 4d 1a 2b"));
        assert!(stored_by_old_menu_link("vmware-56", "VMware-56 4d"));
        assert!(!stored_by_old_menu_link("VMware-56", "VMware-56"));
        assert!(!stored_by_old_menu_link("VMware-57", "VMware-56 4d"));
        assert!(!stored_by_old_menu_link("VMware", "VMware-56 4d"));
    }

    #[test]
    fn serial_comparison_ignores_case_only() {
        assert!(same_serial("5cg1234xyz", "5CG1234XYZ"));
        assert!(!same_serial("5CG1234XYZ", "5CG1234XY0"));
    }

    #[test]
    fn usable_uuids_are_normalised_like_the_agent_does() {
        assert_eq!(
            usable_uuid(" 4C4C4544-0042-3510-8051-B4C04F4E3732\n").as_deref(),
            Some("4c4c4544-0042-3510-8051-b4c04f4e3732")
        );
        for value in [
            "",
            "   ",
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "03000200-0400-0500-0006-000700080009",
            "0123-4567",
            "4c4c4544-0042-3510-8051-b4c04f4e3732-extra-text",
        ] {
            assert_eq!(usable_uuid(value), None, "{value}");
        }
    }

    #[test]
    fn the_uuid_fingerprint_is_the_agents_hardware_fingerprint() {
        // sha256("tiaris-hardware-v1\ndmi_product_uuid=<uuid>"), as the Tiaris
        // agent's `hardware_fingerprint_from_material` computes it.
        let fingerprint = uuid_fingerprint("4c4c4544-0042-3510-8051-b4c04f4e3732");
        assert_eq!(
            fingerprint,
            "249a7176b8027b27144ebdd8698e294edc1d7960e51f2800052ac8eddbde7115"
        );
        assert!(is_fingerprint(&fingerprint));
        assert!(!is_fingerprint(&fingerprint.to_ascii_uppercase()));
        assert!(!is_fingerprint(&fingerprint[..63]));
    }
}
