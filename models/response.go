package models

// RiskAnalysisAPIResponse wraps the parsed response together with HTTP metadata,
// following the same pattern as the CyberSource REST SDK.
type RiskAnalysisAPIResponse struct {
	// HTTPStatus is the HTTP status code returned by CyberSource.
	HTTPStatus int

	// Body is the raw SOAP XML response body.
	Body []byte

	// Data is the parsed risk analysis response.
	Data RiskAnalysisResponse
}

// RiskAnalysisResponse contains the parsed Decision Manager response.
type RiskAnalysisResponse struct {
	// RequestID is the CyberSource-assigned request identifier.
	RequestID string

	// Decision is the risk decision: ACCEPT, REVIEW, or REJECT.
	Decision string

	// ReasonCode is the numeric reason code (100 = accept, 480 = soft reject, 481 = hard reject).
	ReasonCode int

	// RequestToken is the opaque token for follow-up requests.
	RequestToken string

	// MerchantReferenceCode is echoed back from the request.
	MerchantReferenceCode string

	// AFSReply contains the Advanced Fraud Screen scoring details.
	// Nil when AFS data is not available (e.g. on errors).
	AFSReply *AFSReply
}

// AFSReply contains the Advanced Fraud Screen scoring and risk factor details.
type AFSReply struct {
	ReasonCode      int
	AFSResult       string // Numeric score as string
	HostSeverity    string
	AFSFactorCode   string // Risk factor codes separated by "^"
	AddressInfoCode string
	IPCountry       string
	IPState         string
	IPCity          string
	ScoreModelUsed  string
	BinCountry      string
	CardScheme      string
	CardIssuer      string
}

// Risk decision constants.
const (
	DecisionAccept = "ACCEPT"
	DecisionReview = "REVIEW"
	DecisionReject = "REJECT"
)
