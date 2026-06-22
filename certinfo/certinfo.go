package certinfo

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/helpers"
)

// Certificate represents a JSON description of an X.509 certificate.
type Certificate struct {
	Subject            Name      `json:"subject,omitempty"`
	Issuer             Name      `json:"issuer,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	SANs               []string  `json:"sans,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"sigalg"`
	AKI                string    `json:"authority_key_id"`
	SKI                string    `json:"subject_key_id"`
	RawPEM             string    `json:"pem"`
	ExpiringSoon       bool      `json:"expiring_soon,omitempty"`
	DaysUntilExpiry    int       `json:"days_until_expiry,omitempty"`
}

// Name represents a JSON description of a PKIX Name
type Name struct {
	CommonName         string        `json:"common_name,omitempty"`
	SerialNumber       string        `json:"serial_number,omitempty"`
	Country            string        `json:"country,omitempty"`
	Countries          []string      `json:"countries,omitempty"`
	Organization       string        `json:"organization,omitempty"`
	Organizations      []string      `json:"organizations,omitempty"`
	OrganizationalUnit string        `json:"organizational_unit,omitempty"`
	OrganizationalUnits []string     `json:"organizational_units,omitempty"`
	Locality           string        `json:"locality,omitempty"`
	Localities         []string      `json:"localities,omitempty"`
	Province           string        `json:"province,omitempty"`
	Provinces          []string      `json:"provinces,omitempty"`
	StreetAddress      string        `json:"street_address,omitempty"`
	StreetAddresses    []string      `json:"street_addresses,omitempty"`
	PostalCode         string        `json:"postal_code,omitempty"`
	PostalCodes        []string      `json:"postal_codes,omitempty"`
	Names              []interface{} `json:"names,omitempty"`
}

// ParseName parses a new name from a *pkix.Name
func ParseName(name pkix.Name) Name {
	n := Name{
		CommonName:          name.CommonName,
		SerialNumber:        name.SerialNumber,
		Countries:           append([]string{}, name.Country...),
		Organizations:       append([]string{}, name.Organization...),
		OrganizationalUnits: append([]string{}, name.OrganizationalUnit...),
		Localities:          append([]string{}, name.Locality...),
		Provinces:           append([]string{}, name.Province...),
		StreetAddresses:     append([]string{}, name.StreetAddress...),
		PostalCodes:         append([]string{}, name.PostalCode...),
	}

	if len(name.Country) > 0 {
		n.Country = strings.Join(name.Country, ",")
	}
	if len(name.Organization) > 0 {
		n.Organization = strings.Join(name.Organization, ",")
	}
	if len(name.OrganizationalUnit) > 0 {
		n.OrganizationalUnit = strings.Join(name.OrganizationalUnit, ",")
	}
	if len(name.Locality) > 0 {
		n.Locality = strings.Join(name.Locality, ",")
	}
	if len(name.Province) > 0 {
		n.Province = strings.Join(name.Province, ",")
	}
	if len(name.StreetAddress) > 0 {
		n.StreetAddress = strings.Join(name.StreetAddress, ",")
	}
	if len(name.PostalCode) > 0 {
		n.PostalCode = strings.Join(name.PostalCode, ",")
	}

	for i := range name.Names {
		n.Names = append(n.Names, name.Names[i].Value)
	}

	return n
}

func formatKeyID(id []byte) string {
	var s string

	for i, c := range id {
		if i > 0 {
			s += ":"
		}
		s += fmt.Sprintf("%02X", c)
	}

	return s
}

// ParseCertificate parses an x509 certificate.
func ParseCertificate(cert *x509.Certificate) *Certificate {
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	c := &Certificate{
		RawPEM:             string(helpers.EncodeCertificatePEM(cert)),
		SignatureAlgorithm: helpers.SignatureString(cert.SignatureAlgorithm),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		Subject:            ParseName(cert.Subject),
		Issuer:             ParseName(cert.Issuer),
		SANs:               cert.DNSNames,
		AKI:                formatKeyID(cert.AuthorityKeyId),
		SKI:                formatKeyID(cert.SubjectKeyId),
		SerialNumber:       cert.SerialNumber.String(),
		ExpiringSoon:       daysUntilExpiry <= 30,
		DaysUntilExpiry:    daysUntilExpiry,
	}
	for _, ip := range cert.IPAddresses {
		c.SANs = append(c.SANs, ip.String())
	}
	if c.ExpiringSoon {
		fmt.Fprintf(os.Stderr, "WARNING: Certificate %q will expire in %d days (on %s)\n",
			cert.Subject.CommonName, daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
	}
	return c
}

// ParseCertificateFile parses x509 certificate file.
func ParseCertificateFile(certFile string) (*Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return ParseCertificatePEM(certPEM)
}

// ParseCertificatePEM parses an x509 certificate PEM.
func ParseCertificatePEM(certPEM []byte) (*Certificate, error) {
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	return ParseCertificate(cert), nil
}

// ParseCSRPEM uses the helper to parse an x509 CSR PEM.
func ParseCSRPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	csrObject, err := helpers.ParseCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}

	return csrObject, nil
}

// ParseCSRFile uses the helper to parse an x509 CSR PEM file.
func ParseCSRFile(csrFile string) (*x509.CertificateRequest, error) {
	csrPEM, err := os.ReadFile(csrFile)
	if err != nil {
		return nil, err
	}

	return ParseCSRPEM(csrPEM)
}

// ParseCertificateDomain parses the certificate served by the given domain.
func ParseCertificateDomain(domain string) (cert *Certificate, err error) {
	var host, port string
	if host, port, err = net.SplitHostPort(domain); err != nil {
		host = domain
		port = "443"
	}

	var conn *tls.Conn
	conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return nil, errors.New("received no server certificates")
	}

	cert = ParseCertificate(conn.ConnectionState().PeerCertificates[0])
	return
}

// ParseSerialNumber parses the serial number and does a lookup in the data
// storage used for certificates. The authority key is required for the lookup
// to work and must be passed as a hex string.
func ParseSerialNumber(serial, aki string, dbAccessor certdb.Accessor) (*Certificate, error) {
	normalizedAKI := strings.ToLower(aki)
	normalizedAKI = strings.Replace(normalizedAKI, ":", "", -1)

	certificates, err := dbAccessor.GetCertificate(serial, normalizedAKI)
	if err != nil {
		return nil, err
	}

	if len(certificates) < 1 {
		return nil, errors.New("no certificate found")
	}

	if len(certificates) > 1 {
		return nil, errors.New("more than one certificate found")
	}

	return ParseCertificatePEM([]byte(certificates[0].PEM))
}
