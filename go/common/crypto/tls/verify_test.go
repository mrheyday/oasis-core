package tls

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestVerifyCertificate(t *testing.T) {
	require := require.New(t)

	cert, err := Generate("my-common-name")
	require.NoError(err, "Generate")

	signer := memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey))
	signer2 := memory.NewTestSigner("common/crypto/tls: test signer")

	certs := make([]*x509.Certificate, 0)
	for _, der := range cert.Certificate {
		c, err := x509.ParseCertificate(der)
		require.NoError(err, "ParseCertificate")
		certs = append(certs, c)
	}

	err = VerifyCertificates(certs, VerifyOptions{
		CommonName: "my-common-name",
		Keys: map[signature.PublicKey]bool{
			signer.Public(): true,
		},
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificates(certs, VerifyOptions{
		CommonName:       "my-common-name",
		AllowUnknownKeys: true,
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificates(nil, VerifyOptions{
		CommonName:         "my-common-name",
		AllowNoCertificate: true,
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificates(certs, VerifyOptions{
		CommonName: "other-common-name",
		Keys: map[signature.PublicKey]bool{
			signer.Public(): true,
		},
	})
	require.Error(err, "VerifyCertificate should fail with mismatched common name")

	err = VerifyCertificates(certs, VerifyOptions{
		CommonName: "my-common-name",
		Keys: map[signature.PublicKey]bool{
			signer2.Public(): true,
		},
	})
	require.Error(err, "VerifyCertificate should fail with mismatched public key")
}
