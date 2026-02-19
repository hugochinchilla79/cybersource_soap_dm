package cybersource_soap_dm

// DetectCardBrand returns the card brand name based on the card number (BIN/IIN).
// Returns: "visa", "mastercard", "amex", "discover", or "" if unknown.
func DetectCardBrand(number string) string {
	if len(number) < 1 {
		return ""
	}

	// Visa: starts with 4
	if number[0] == '4' {
		return "visa"
	}

	// Amex: starts with 34 or 37
	if len(number) >= 2 {
		p2 := number[:2]
		if p2 == "34" || p2 == "37" {
			return "amex"
		}
	}

	// Mastercard: 51-55 or 2221-2720
	if len(number) >= 2 {
		p2 := number[:2]
		if p2 >= "51" && p2 <= "55" {
			return "mastercard"
		}
		if len(number) >= 4 {
			p4 := number[:4]
			if p4 >= "2221" && p4 <= "2720" {
				return "mastercard"
			}
		}
	}

	// Discover: 6011, 622126-622925, 644-649, 65
	if len(number) >= 2 {
		if number[:2] == "65" {
			return "discover"
		}
		if len(number) >= 3 {
			p3 := number[:3]
			if p3 >= "644" && p3 <= "649" {
				return "discover"
			}
		}
		if len(number) >= 4 && number[:4] == "6011" {
			return "discover"
		}
		if len(number) >= 6 {
			p6 := number[:6]
			if p6 >= "622126" && p6 <= "622925" {
				return "discover"
			}
		}
	}

	return ""
}

// CyberSourceCardTypeCode maps a card brand name to the CyberSource card type code.
var CyberSourceCardTypeCode = map[string]string{
	"visa":       "001",
	"mastercard": "002",
	"amex":       "003",
	"discover":   "004",
}
