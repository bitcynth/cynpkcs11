package cynpkcs11

import (
	"crypto"
	"crypto/rsa"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

type Signer struct {
	crypto.Signer
	context *Context
}

// Initialize initializes all the things
func (signer *Signer) Initialize() error {
	// Find the private key
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_SIGN, true)}
	err := signer.context.ctx.FindObjectsInit(signer.context.session, temp)
	if err != nil {
		return err
	}

	objs, _, err := signer.context.ctx.FindObjects(signer.context.session, 100)
	if err != nil {
		return err
	}
	signer.context.ctx.FindObjectsFinal(signer.context.session)

	signer.context.privateKey = objs[0]

	// Find the public key
	temp2 := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true)}
	err = signer.context.ctx.FindObjectsInit(signer.context.session, temp2)
	if err != nil {
		return err
	}

	objs2, _, err := signer.context.ctx.FindObjects(signer.context.session, 100)
	if err != nil {
		return err
	}
	signer.context.ctx.FindObjectsFinal(signer.context.session)

	signer.context.publicKey = objs2[0]

	return nil
}

func (signer *Signer) Public() crypto.PublicKey {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{})}
	attr, err := signer.context.ctx.GetAttributeValue(signer.context.session, signer.context.publicKey, temp)
	if err != nil {
		panic(err)
	}

	temp2 := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{})}
	attr2, err := signer.context.ctx.GetAttributeValue(signer.context.session, signer.context.publicKey, temp2)
	if err != nil {
		panic(err)
	}

	modulus := new(big.Int)
	publicExponent := new(big.Int)

	modulus.SetBytes(attr[0].Value)
	publicExponent.SetBytes(attr2[0].Value)

	pubKey := &rsa.PublicKey{
		E: int(publicExponent.Int64()),
		N: modulus,
	}

	return pubKey
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Sign the data in the input buffer
	err := signer.context.ctx.SignInit(signer.context.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, nil)}, signer.context.privateKey)
	if err != nil {
		return nil, err
	}

	sig, err := signer.context.ctx.Sign(signer.context.session, digest)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
