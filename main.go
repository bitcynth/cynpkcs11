package cynpkcs11

import "github.com/miekg/pkcs11"

// Context represents a handle for a "session"
type Context struct {
	Signer     *Signer
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	publicKey  pkcs11.ObjectHandle
}

// ContextOptions represents the options that are used to create and initialize the context
type ContextOptions struct {
	PKCS11Module string
	PIN          string
}

// New creates a signer and initializes it
func New(opts ContextOptions) (*Context, error) {
	context := &Context{}
	context.Signer = &Signer{
		context: context,
	}
	return context, context.Initialize(opts)
}

func (context *Context) Initialize(opts ContextOptions) error {
	// Create and initialize the PKCS#11 context
	context.ctx = pkcs11.New(opts.PKCS11Module)
	err := context.ctx.Initialize()
	if err != nil {
		return err
	}

	slots, err := context.ctx.GetSlotList(true)
	if err != nil {
		return err
	}

	context.session, err = context.ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}

	err = context.ctx.Login(context.session, pkcs11.CKU_USER, opts.PIN)
	if err != nil {
		return err
	}

	return nil
}

// Close cleans up the PKCS#11 objects
func (context *Context) Close() {
	context.ctx.Logout(context.session)
	context.ctx.CloseSession(context.session)

	context.ctx.Finalize()
	context.ctx.Destroy()
}
