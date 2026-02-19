package cybersource_soap_dm

import (
	"encoding/xml"
	"fmt"
	"sort"
)

// ============================================
// SOAP Request Structures (internal marshaling)
// ============================================

type soapEnvelope struct {
	XMLName xml.Name `xml:"SOAP-ENV:Envelope"`
	SoapNS  string   `xml:"xmlns:SOAP-ENV,attr"`
	CybsNS  string   `xml:"xmlns:ns1,attr"`
	Header  string   `xml:"SOAP-ENV:Header"`
	Body    soapBody `xml:"SOAP-ENV:Body"`
}

type soapBody struct {
	RequestMessage requestMessage `xml:"ns1:requestMessage"`
}

type requestMessage struct {
	MerchantID            string          `xml:"ns1:merchantID"`
	MerchantReferenceCode string          `xml:"ns1:merchantReferenceCode"`
	ClientLibrary         string          `xml:"ns1:clientLibrary"`
	ClientLibraryVersion  string          `xml:"ns1:clientLibraryVersion"`
	ClientEnvironment     string          `xml:"ns1:clientEnvironment,omitempty"`
	BillTo                *soapBillTo     `xml:"ns1:billTo,omitempty"`
	Items                 []soapItem      `xml:"ns1:item,omitempty"`
	PurchaseTotals        *soapPurchase   `xml:"ns1:purchaseTotals,omitempty"`
	Card                  *soapCard       `xml:"ns1:card,omitempty"`
	MerchantDefinedData   *soapMDD        `xml:"ns1:merchantDefinedData,omitempty"`
	AFSService            *soapAFSService `xml:"ns1:afsService,omitempty"`
	DeviceFingerprintID   string          `xml:"ns1:deviceFingerprintID,omitempty"`
}

type soapBillTo struct {
	FirstName   string `xml:"ns1:firstName"`
	LastName    string `xml:"ns1:lastName"`
	Street1     string `xml:"ns1:street1,omitempty"`
	City        string `xml:"ns1:city,omitempty"`
	State       string `xml:"ns1:state,omitempty"`
	PostalCode  string `xml:"ns1:postalCode,omitempty"`
	Country     string `xml:"ns1:country,omitempty"`
	PhoneNumber string `xml:"ns1:phoneNumber,omitempty"`
	Email       string `xml:"ns1:email,omitempty"`
	IPAddress   string `xml:"ns1:ipAddress,omitempty"`
	CustomerID  string `xml:"ns1:customerID,omitempty"`
}

type soapCard struct {
	AccountNumber   string `xml:"ns1:accountNumber"`
	ExpirationMonth string `xml:"ns1:expirationMonth"`
	ExpirationYear  string `xml:"ns1:expirationYear"`
	CardType        string `xml:"ns1:cardType,omitempty"`
	Bin             string `xml:"ns1:bin,omitempty"`
}

type soapItem struct {
	XMLName     xml.Name `xml:"ns1:item"`
	ID          int      `xml:"id,attr"`
	UnitPrice   string   `xml:"ns1:unitPrice"`
	Quantity    int      `xml:"ns1:quantity"`
	ProductCode string   `xml:"ns1:productCode,omitempty"`
	ProductName string   `xml:"ns1:productName"`
	ProductSKU  string   `xml:"ns1:productSKU,omitempty"`
}

type soapPurchase struct {
	Currency         string `xml:"ns1:currency"`
	GrandTotalAmount string `xml:"ns1:grandTotalAmount"`
}

type soapAFSService struct {
	Run string `xml:"run,attr"`
}

type soapMDD struct {
	Fields map[int]string
}

func (m soapMDD) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	keys := make([]int, 0, len(m.Fields))
	for k := range m.Fields {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fieldName := fmt.Sprintf("ns1:field%d", k)
		el := xml.StartElement{Name: xml.Name{Local: fieldName}}
		if err := e.EncodeElement(m.Fields[k], el); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// ============================================
// SOAP Response Structures
// ============================================

type soapResponseEnvelope struct {
	XMLName xml.Name         `xml:"Envelope"`
	Body    soapResponseBody `xml:"Body"`
}

type soapResponseBody struct {
	ReplyMessage soapReplyMessage `xml:"replyMessage"`
	Fault        *soapFaultBody   `xml:"Fault"`
}

type soapReplyMessage struct {
	MerchantReferenceCode string        `xml:"merchantReferenceCode"`
	RequestID             string        `xml:"requestID"`
	Decision              string        `xml:"decision"`
	ReasonCode            int           `xml:"reasonCode"`
	RequestToken          string        `xml:"requestToken"`
	AFSReply              *soapAFSReply `xml:"afsReply"`
}

type soapAFSReply struct {
	ReasonCode      int    `xml:"reasonCode"`
	AFSResult       string `xml:"afsResult"`
	HostSeverity    string `xml:"hostSeverity"`
	AFSFactorCode   string `xml:"afsFactorCode"`
	AddressInfoCode string `xml:"addressInfoCode"`
	IPCountry       string `xml:"ipCountry"`
	IPState         string `xml:"ipState"`
	IPCity          string `xml:"ipCity"`
	ScoreModelUsed  string `xml:"scoreModelUsed"`
	BinCountry      string `xml:"binCountry"`
	CardScheme      string `xml:"cardScheme"`
	CardIssuer      string `xml:"cardIssuer"`
}

type soapFaultBody struct {
	FaultCode   string `xml:"faultcode"`
	FaultString string `xml:"faultstring"`
}
