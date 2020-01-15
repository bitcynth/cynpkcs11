package cynpkcs11

import (
	"crypto"
	"crypto/rsa"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

type SignerOptions struct {
	PKCS11Module string
	PIN          string
}

type Signer struct {
	crypto.Signer
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	publicKey  pkcs11.ObjectHandle
}

// New creates a signer and initializes it
func New(opts SignerOptions) (*Signer, error) {
	signer := &Signer{}
	return signer, signer.Initialize(opts)
}

// Initialize initializes all the things
func (signer *Signer) Initialize(opts SignerOptions) error {
	// Create and initialize the PKCS#11 context
	signer.ctx = pkcs11.New(opts.PKCS11Module)
	err := signer.ctx.Initialize()
	if err != nil {
		return err
	}

	slots, err := signer.ctx.GetSlotList(true)
	if err != nil {
		return err
	}

	signer.session, err = signer.ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}

	err = signer.ctx.Login(signer.session, pkcs11.CKU_USER, opts.PIN)
	if err != nil {
		return err
	}

	// Find the private key
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_SIGN, true)}
	err = signer.ctx.FindObjectsInit(signer.session, temp)
	if err != nil {
		return err
	}

	objs, _, err := signer.ctx.FindObjects(signer.session, 100)
	if err != nil {
		return err
	}
	signer.ctx.FindObjectsFinal(signer.session)

	signer.privateKey = objs[0]

	// Find the public key
	temp2 := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true)}
	err = signer.ctx.FindObjectsInit(signer.session, temp2)
	if err != nil {
		return err
	}

	objs2, _, err := signer.ctx.FindObjects(signer.session, 100)
	if err != nil {
		return err
	}
	signer.ctx.FindObjectsFinal(signer.session)

	signer.publicKey = objs2[0]

	return nil
}

// Close cleans up the PKCS#11 objects
func (signer *Signer) Close() {
	signer.ctx.Logout(signer.session)
	signer.ctx.CloseSession(signer.session)

	signer.ctx.Finalize()
	signer.ctx.Destroy()
}

func (signer *Signer) Public() crypto.PublicKey {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{})}
	attr, err := signer.ctx.GetAttributeValue(signer.session, signer.publicKey, temp)
	if err != nil {
		panic(err)
	}

	temp2 := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{})}
	attr2, err := signer.ctx.GetAttributeValue(signer.session, signer.publicKey, temp2)
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
	err := signer.ctx.SignInit(signer.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, signer.privateKey)
	if err != nil {
		return nil, err
	}

	sig, err := signer.ctx.Sign(signer.session, digest)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
