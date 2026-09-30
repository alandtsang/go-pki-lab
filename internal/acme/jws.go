package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

type jwsEnvelope struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type protectedHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
	KID   string          `json:"kid,omitempty"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type verifiedJWS struct {
	Header    protectedHeader
	Payload   []byte
	PublicKey crypto.PublicKey
	JWK       json.RawMessage
}

func decodeJWS(body []byte) (jwsEnvelope, protectedHeader, []byte, []byte, error) {
	var env jwsEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return env, protectedHeader{}, nil, nil, fmt.Errorf("decode JWS: %w", err)
	}
	if env.Protected == "" || env.Signature == "" {
		return env, protectedHeader{}, nil, nil, fmt.Errorf("JWS protected and signature fields are required")
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return env, protectedHeader{}, nil, nil, fmt.Errorf("decode JWS protected header: %w", err)
	}
	var header protectedHeader
	if err := json.Unmarshal(protectedJSON, &header); err != nil {
		return env, protectedHeader{}, nil, nil, fmt.Errorf("parse JWS protected header: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return env, protectedHeader{}, nil, nil, fmt.Errorf("decode JWS payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		return env, protectedHeader{}, nil, nil, fmt.Errorf("decode JWS signature: %w", err)
	}
	return env, header, payload, sig, nil
}

func parseJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("JWK is required")
	}
	var key jwk
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}
	switch key.Kty {
	case "EC":
		if key.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve %q", key.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, fmt.Errorf("decode JWK x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, fmt.Errorf("decode JWK y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("JWK EC point is not on P-256")
		}
		return pub, nil
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("decode JWK modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("decode JWK exponent: %w", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e <= 0 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", key.Kty)
	}
}

func verifyJWSSignature(env jwsEnvelope, header protectedHeader, signature []byte, publicKey crypto.PublicKey) error {
	signingInput := []byte(env.Protected + "." + env.Payload)
	digest := sha256.Sum256(signingInput)

	switch header.Alg {
	case "ES256":
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ES256 requires an EC public key")
		}
		if len(signature) != 64 {
			return fmt.Errorf("invalid ES256 signature length")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("invalid ES256 signature")
		}
		return nil
	case "RS256":
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RS256 requires an RSA public key")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("invalid RS256 signature: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWS algorithm %q", header.Alg)
	}
}

func jwkThumbprint(raw json.RawMessage) (string, error) {
	var key jwk
	if err := json.Unmarshal(raw, &key); err != nil {
		return "", fmt.Errorf("parse JWK for thumbprint: %w", err)
	}
	var canonical []byte
	var err error
	switch key.Kty {
	case "EC":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{Crv: key.Crv, Kty: key.Kty, X: key.X, Y: key.Y})
	case "RSA":
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{E: key.E, Kty: key.Kty, N: key.N})
	default:
		return "", fmt.Errorf("unsupported JWK key type %q", key.Kty)
	}
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
