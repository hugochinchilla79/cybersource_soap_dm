package models

// RiskAnalysisRequest is the input for a Decision Manager risk analysis call.
type RiskAnalysisRequest struct {
	// MerchantReferenceCode is a unique reference for this transaction.
	MerchantReferenceCode string

	// BillTo contains the customer billing address and contact info.
	BillTo *BillTo

	// Card contains the payment card details.
	Card Card

	// Items is a list of line items in the transaction.
	Items []Item

	// PurchaseTotals contains the total amount and currency.
	PurchaseTotals PurchaseTotals

	// MerchantDefinedData is a map of field number (1-20) to value.
	// These are custom merchant fields used for risk analysis rules.
	MerchantDefinedData map[int]string

	// DeviceFingerprintID is the device fingerprint session identifier.
	DeviceFingerprintID string
}

// BillTo contains customer billing and contact information.
type BillTo struct {
	FirstName   string
	LastName    string
	Street1     string
	City        string
	State       string
	PostalCode  string
	Country     string
	PhoneNumber string
	Email       string
	IPAddress   string
	CustomerID  string
}

// Card contains payment card details.
type Card struct {
	// Number is the full card number (PAN).
	Number string

	// ExpirationMonth is the two-digit expiration month (e.g. "12").
	ExpirationMonth string

	// ExpirationYear is the four-digit expiration year (e.g. "2027").
	ExpirationYear string

	// CardType is the CyberSource card type code (e.g. "001" for Visa).
	// If empty, it is auto-detected from the card Number.
	CardType string
}

// Item represents a line item in the transaction.
type Item struct {
	UnitPrice   string
	Quantity    int
	ProductCode string
	ProductName string
	ProductSKU  string
}

// PurchaseTotals contains the total amount and currency for the transaction.
type PurchaseTotals struct {
	Currency         string
	GrandTotalAmount string
}
