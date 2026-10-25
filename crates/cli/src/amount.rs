//! TARI amounts: the CLI takes decimal TARI, the chain counts µT (1 TARI = 1,000,000 µT).

use anyhow::{Result, anyhow, bail};
use tari_template_lib_types::Amount;

pub const MICRO: u64 = 1_000_000;

/// Parses `"5"`, `"0.05"` or `"1.000001"` TARI into µT.
pub fn parse_tari(s: &str) -> Result<u64> {
    let s = s.trim();
    let s = s.strip_suffix("tTARI").or_else(|| s.strip_suffix("TARI")).unwrap_or(s).trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() {
        bail!("empty amount");
    }
    if frac.len() > 6 {
        bail!("at most 6 decimal places (1 µT)");
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| anyhow!("bad amount {s:?}"))? };
    let frac: u64 =
        if frac.is_empty() { 0 } else { format!("{frac:0<6}").parse().map_err(|_| anyhow!("bad amount {s:?}"))? };
    whole.checked_mul(MICRO).and_then(|w| w.checked_add(frac)).ok_or_else(|| anyhow!("amount too large"))
}

pub fn format_tari(a: Amount) -> String {
    let v = a.to_u128();
    let whole = v / MICRO as u128;
    let frac = v % MICRO as u128;
    if frac == 0 {
        format!("{whole} tTARI")
    } else {
        let f = format!("{frac:06}");
        format!("{whole}.{} tTARI", f.trim_end_matches('0'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_tari() {
        assert_eq!(parse_tari("5").unwrap(), 5_000_000);
        assert_eq!(parse_tari("0.05").unwrap(), 50_000);
        assert_eq!(parse_tari(".5").unwrap(), 500_000);
        assert_eq!(parse_tari("1.000001").unwrap(), 1_000_001);
        assert!(parse_tari("1.0000001").is_err());
        assert!(parse_tari("x").is_err());
        assert!(parse_tari("").is_err());
        assert_eq!(parse_tari("5.5 tTARI").unwrap(), 5_500_000);
        assert_eq!(parse_tari("2 TARI").unwrap(), 2_000_000);
    }

    #[test]
    fn formats_tari() {
        assert_eq!(format_tari(Amount::from(5_000_000u64)), "5 tTARI");
        assert_eq!(format_tari(Amount::from(4_950_000u64)), "4.95 tTARI");
    }
}
