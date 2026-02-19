package cybersource_soap_dm

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	wsuNS  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	wsseNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	soapNS = "http://schemas.xmlsoap.org/soap/envelope/"
	dsNS   = "http://www.w3.org/2000/09/xmldsig#"
	cybsNS = "urn:schemas-cybersource-com:transaction-data-1.111"

	algExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algSha256    = "http://www.w3.org/2001/04/xmlenc#sha256"
)

// signSOAPEnvelope injects a wsse:Security header into the SOAP envelope containing:
//   - wsse:BinarySecurityToken (X.509 leaf cert, DER base64)
//   - ds:Signature with SignedInfo referencing "#Body" (exclusive C14N, RSA-SHA256)
//   - ds:KeyInfo → wsse:SecurityTokenReference → wsse:Reference URI="#X509Token"
func signSOAPEnvelope(unsignedXML []byte, tlsCert tls.Certificate) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(unsignedXML); err != nil {
		return nil, fmt.Errorf("parse soap xml: %w", err)
	}

	env := doc.Root()
	if env == nil {
		return nil, fmt.Errorf("soap envelope missing")
	}

	// Locate Header and Body
	header := findChild(env, "Header")
	body := findChild(env, "Body")
	if body == nil {
		return nil, fmt.Errorf("soap Body not found")
	}
	if header == nil {
		header = etree.NewElement("SOAP-ENV:Header")
		env.InsertChildAt(0, header)
	}

	// Declare namespaces on Body and requestMessage so that the
	// goxmldsig exclusive C14N canonicalizer can resolve prefixes
	// (it cannot walk above the canonicalized subtree root).
	ensureXMLNS(body, "SOAP-ENV", soapNS)
	ensureXMLNS(body, "wsu", wsuNS)
	if rm := findChild(body, "requestMessage"); rm != nil {
		ensureXMLNS(rm, "ns1", cybsNS)
	}

	// Mark Body with wsu:Id="Body"
	body.RemoveAttr("wsu:Id")
	body.CreateAttr("wsu:Id", "Body")

	// --- Build complete Security header (PHP-style local namespace scoping) ---
	leaf, err := leafCertFromTLS(tlsCert)
	if err != nil {
		return nil, err
	}
	privKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA (got %T)", tlsCert.PrivateKey)
	}

	// wsse:Security (xmlns:wsse declared here, not on Envelope)
	security := etree.NewElement("wsse:Security")
	ensureXMLNS(security, "wsse", wsseNS)
	header.AddChild(security)

	// wsse:BinarySecurityToken (xmlns:wsu declared here for wsu:Id)
	bst := etree.NewElement("wsse:BinarySecurityToken")
	ensureXMLNS(bst, "wsu", wsuNS)
	bst.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	bst.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	bst.CreateAttr("wsu:Id", "X509Token")
	bst.SetText(base64.StdEncoding.EncodeToString(leaf.Raw))
	security.AddChild(bst)

	// ds:Signature (xmlns:ds declared here, not on Envelope)
	sig := etree.NewElement("ds:Signature")
	ensureXMLNS(sig, "ds", dsNS)
	security.AddChild(sig)

	// ds:SignedInfo — also needs xmlns:ds for C14N resolution
	signedInfo := etree.NewElement("ds:SignedInfo")
	ensureXMLNS(signedInfo, "ds", dsNS)
	sig.AddChild(signedInfo)

	cm := etree.NewElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", algExcC14N)
	signedInfo.AddChild(cm)

	sm := etree.NewElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", algRsaSha256)
	signedInfo.AddChild(sm)

	ref := etree.NewElement("ds:Reference")
	ref.CreateAttr("URI", "#Body")
	signedInfo.AddChild(ref)

	transforms := etree.NewElement("ds:Transforms")
	ref.AddChild(transforms)
	tr := etree.NewElement("ds:Transform")
	tr.CreateAttr("Algorithm", algExcC14N)
	transforms.AddChild(tr)

	dm := etree.NewElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", algSha256)
	ref.AddChild(dm)

	dv := etree.NewElement("ds:DigestValue")
	ref.AddChild(dv)

	sv := etree.NewElement("ds:SignatureValue")
	sig.AddChild(sv)

	ki := etree.NewElement("ds:KeyInfo")
	sig.AddChild(ki)
	str := etree.NewElement("wsse:SecurityTokenReference")
	ki.AddChild(str)
	ref2 := etree.NewElement("wsse:Reference")
	ref2.CreateAttr("URI", "#X509Token")
	str.AddChild(ref2)

	// Remove wsse/wsu/ds from Envelope — they're declared locally now
	env.RemoveAttr("xmlns:wsse")
	env.RemoveAttr("xmlns:wsu")
	env.RemoveAttr("xmlns:ds")

	// Indent BEFORE computing digest/signature so the canonical form
	// matches the serialized output exactly.
	doc.Indent(2)

	// DigestValue = SHA-256( C14N(exclusive) of Body )
	bodyC14N, err := exclusiveC14N(body)
	if err != nil {
		return nil, fmt.Errorf("c14n body: %w", err)
	}
	dv.SetText(base64.StdEncoding.EncodeToString(sha256Sum(bodyC14N)))

	// SignatureValue = RSA-SHA256( C14N(exclusive) of SignedInfo )
	signedInfoC14N, err := exclusiveC14N(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("c14n signedInfo: %w", err)
	}
	hashed := sha256Sum(signedInfoC14N)
	signature, err := rsa.SignPKCS1v15(nil, privKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, fmt.Errorf("rsa sign: %w", err)
	}
	sv.SetText(base64.StdEncoding.EncodeToString(signature))

	// Serialize (tree is in final form — do not re-indent)
	out := bytes.NewBuffer(nil)
	if _, err := doc.WriteTo(out); err != nil {
		return nil, fmt.Errorf("serialize signed xml: %w", err)
	}
	return out.Bytes(), nil
}

// ============================================
// XML helpers
// ============================================

func ensureXMLNS(el *etree.Element, prefix, uri string) {
	attrName := "xmlns:" + prefix
	for _, a := range el.Attr {
		if a.Key == attrName {
			return
		}
	}
	el.CreateAttr(attrName, uri)
}

func findChild(parent *etree.Element, localName string) *etree.Element {
	for _, c := range parent.ChildElements() {
		tag := c.Tag
		if tag == localName {
			return c
		}
		if idx := strings.LastIndex(tag, ":"); idx >= 0 {
			if tag[idx+1:] == localName {
				return c
			}
		}
	}
	return nil
}

func leafCertFromTLS(cert tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("tls cert has no certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	return leaf, nil
}

func exclusiveC14N(node *etree.Element) ([]byte, error) {
	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return canon.Canonicalize(node)
}

func sha256Sum(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}
