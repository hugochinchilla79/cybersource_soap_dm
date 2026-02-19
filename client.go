package cybersource_soap_dm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/hugochinchilla79/cybersource_soap_dm_sdk/models"
)

// Client interacts with the CyberSource Decision Manager SOAP API.
type Client struct {
	cfg        Config
	httpClient *http.Client
	soapURL    string
	tlsCert    tls.Certificate
}

// NewClient creates a new Decision Manager SOAP client.
// It validates the configuration, loads the P12 certificate, and prepares
// a TLS-configured HTTP client.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	tlsCert, err := loadP12Certificate(cfg.P12Path, cfg.P12Password)
	if err != nil {
		return nil, fmt.Errorf("cybersource_soap_dm: failed to load P12 certificate: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
		soapURL:    cfg.DefaultBaseURL(),
		tlsCert:    tlsCert,
	}, nil
}

// AnalyzeRisk performs a risk analysis request against CyberSource Decision Manager.
func (c *Client) AnalyzeRisk(ctx context.Context, req models.RiskAnalysisRequest) (models.RiskAnalysisAPIResponse, error) {
	// Build SOAP envelope
	envelope := c.buildSOAPRequest(req)

	xmlData, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return models.RiskAnalysisAPIResponse{}, fmt.Errorf("cybersource_soap_dm: marshal SOAP request: %w", err)
	}

	xmlPayload := []byte(xml.Header + string(xmlData))

	// Sign the envelope (inject wsse:Security header with BinarySecurityToken + ds:Signature)
	signedPayload, err := signSOAPEnvelope(xmlPayload, c.tlsCert)
	if err != nil {
		return models.RiskAnalysisAPIResponse{}, fmt.Errorf("cybersource_soap_dm: sign SOAP request: %w", err)
	}

	// Send HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.soapURL, bytes.NewReader(signedPayload))
	if err != nil {
		return models.RiskAnalysisAPIResponse{}, fmt.Errorf("cybersource_soap_dm: create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
	httpReq.Header.Set("SOAPAction", "runTransaction")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return models.RiskAnalysisAPIResponse{}, fmt.Errorf("cybersource_soap_dm: send SOAP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.RiskAnalysisAPIResponse{}, fmt.Errorf("cybersource_soap_dm: read response: %w", err)
	}

	// Parse SOAP response
	var soapResp soapResponseEnvelope
	if err := xml.Unmarshal(respBody, &soapResp); err != nil {
		return models.RiskAnalysisAPIResponse{
			HTTPStatus: resp.StatusCode,
			Body:       respBody,
		}, fmt.Errorf("cybersource_soap_dm: parse SOAP response (HTTP %d): %w", resp.StatusCode, err)
	}

	// Check for SOAP fault
	if soapResp.Body.Fault != nil {
		return models.RiskAnalysisAPIResponse{
			HTTPStatus: resp.StatusCode,
			Body:       respBody,
		}, &SOAPFault{
			FaultCode:   soapResp.Body.Fault.FaultCode,
			FaultString: strings.TrimSpace(soapResp.Body.Fault.FaultString),
			RawBody:     respBody,
		}
	}

	reply := soapResp.Body.ReplyMessage

	result := models.RiskAnalysisResponse{
		RequestID:             reply.RequestID,
		Decision:              reply.Decision,
		ReasonCode:            reply.ReasonCode,
		RequestToken:          reply.RequestToken,
		MerchantReferenceCode: reply.MerchantReferenceCode,
	}

	if reply.AFSReply != nil {
		result.AFSReply = &models.AFSReply{
			ReasonCode:      reply.AFSReply.ReasonCode,
			AFSResult:       reply.AFSReply.AFSResult,
			HostSeverity:    reply.AFSReply.HostSeverity,
			AFSFactorCode:   reply.AFSReply.AFSFactorCode,
			AddressInfoCode: reply.AFSReply.AddressInfoCode,
			IPCountry:       reply.AFSReply.IPCountry,
			IPState:         reply.AFSReply.IPState,
			IPCity:          reply.AFSReply.IPCity,
			ScoreModelUsed:  reply.AFSReply.ScoreModelUsed,
			BinCountry:      reply.AFSReply.BinCountry,
			CardScheme:      reply.AFSReply.CardScheme,
			CardIssuer:      reply.AFSReply.CardIssuer,
		}
	}

	return models.RiskAnalysisAPIResponse{
		HTTPStatus: resp.StatusCode,
		Body:       respBody,
		Data:       result,
	}, nil
}

// buildSOAPRequest transforms the user-facing request model into SOAP XML structures.
func (c *Client) buildSOAPRequest(req models.RiskAnalysisRequest) soapEnvelope {
	msg := requestMessage{
		MerchantID:            c.cfg.MerchantID,
		MerchantReferenceCode: req.MerchantReferenceCode,
		ClientLibrary:         "Go",
		ClientLibraryVersion:  runtime.Version(),
		ClientEnvironment:     runtime.GOOS,
		AFSService:            &soapAFSService{Run: "true"},
		DeviceFingerprintID:   req.DeviceFingerprintID,
	}

	if req.BillTo != nil {
		msg.BillTo = &soapBillTo{
			FirstName:   req.BillTo.FirstName,
			LastName:    req.BillTo.LastName,
			Street1:     req.BillTo.Street1,
			City:        req.BillTo.City,
			State:       req.BillTo.State,
			PostalCode:  req.BillTo.PostalCode,
			Country:     req.BillTo.Country,
			PhoneNumber: req.BillTo.PhoneNumber,
			Email:       req.BillTo.Email,
			IPAddress:   req.BillTo.IPAddress,
			CustomerID:  req.BillTo.CustomerID,
		}
	}

	// Resolve card type: use explicit value or auto-detect from card number
	cardType := req.Card.CardType
	if cardType == "" {
		brand := DetectCardBrand(req.Card.Number)
		cardType = CyberSourceCardTypeCode[brand]
	}

	bin := ""
	if len(req.Card.Number) >= 6 {
		bin = req.Card.Number[:6]
	}

	msg.Card = &soapCard{
		AccountNumber:   req.Card.Number,
		ExpirationMonth: req.Card.ExpirationMonth,
		ExpirationYear:  req.Card.ExpirationYear,
		CardType:        cardType,
		Bin:             bin,
	}

	for i, item := range req.Items {
		msg.Items = append(msg.Items, soapItem{
			ID:          i,
			UnitPrice:   item.UnitPrice,
			Quantity:    item.Quantity,
			ProductCode: item.ProductCode,
			ProductName: item.ProductName,
			ProductSKU:  item.ProductSKU,
		})
	}

	msg.PurchaseTotals = &soapPurchase{
		Currency:         req.PurchaseTotals.Currency,
		GrandTotalAmount: req.PurchaseTotals.GrandTotalAmount,
	}

	if len(req.MerchantDefinedData) > 0 {
		msg.MerchantDefinedData = &soapMDD{
			Fields: req.MerchantDefinedData,
		}
	}

	return soapEnvelope{
		SoapNS: soapNS,
		CybsNS: cybsNS,
		Body: soapBody{
			RequestMessage: msg,
		},
	}
}
