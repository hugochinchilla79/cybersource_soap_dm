package cybersource_soap_dm

import (
	"fmt"
	"net/http"
)

// HTTPError is returned when CyberSource responds with a non-2xx HTTP status.
type HTTPError struct {
	StatusCode int
	Status     string
	Body       []byte
	Headers    http.Header
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("cybersource_soap_dm http error %d (%s): %s", e.StatusCode, e.Status, e.Body)
}

// SOAPFault represents a SOAP fault returned by CyberSource.
type SOAPFault struct {
	FaultCode   string
	FaultString string
	RawBody     []byte
}

func (e *SOAPFault) Error() string {
	return fmt.Sprintf("cybersource_soap_dm soap fault [%s]: %s", e.FaultCode, e.FaultString)
}
