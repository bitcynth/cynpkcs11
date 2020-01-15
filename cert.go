package cynpkcs11

import (
	"crypto/x509"

	"github.com/miekg/pkcs11"
)

func (context *Context) GetCertificates() ([]*x509.Certificate, error) {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509)}
	err := context.ctx.FindObjectsInit(context.session, temp)
	if err != nil {
		return nil, err
	}

	certObjs, _, err := context.ctx.FindObjects(context.session, 1024)
	if err != nil {
		return nil, err
	}
	context.ctx.FindObjectsFinal(context.session)

	var certs []*x509.Certificate

	temp2 := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{})}
	for _, certObj := range certObjs {
		attr, err := context.ctx.GetAttributeValue(context.session, certObj, temp2)
		if err != nil {
			continue
		}

		cert, err := x509.ParseCertificate(attr[0].Value)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
