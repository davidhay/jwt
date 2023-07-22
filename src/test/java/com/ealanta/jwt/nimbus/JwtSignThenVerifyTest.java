package com.ealanta.jwt.nimbus;

import com.ealanta.jwt.BaseJWTTest;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwtSignThenVerifyTest extends BaseJWTTest {

    @Test
    void testGenerateKey() throws JOSEException {

        // Generate 2048-bit RSA key pair in JWK format, attach some metadata
        RSAKey jwk = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(new Date()) // issued-at timestamp (optional)
                .generate();

        // Output the private and public RSA JWK parameters
        System.out.println(jwk);

        // Output the public RSA JWK parameters only
        System.out.println(jwk.toPublicJWK());

        RSAPrivateKey privateKey = (RSAPrivateKey) jwk.toPrivateKey();
        assertEquals("PKCS#8", privateKey.getFormat());
        RSAPublicKey publicKey = (RSAPublicKey) jwk.toPublicKey();
        assertEquals("X.509", publicKey.getFormat());
        assertEquals(privateKey.getModulus(), publicKey.getModulus());
    }

    @Override
    public boolean isSignatureValid(String jwtToken, RSAPublicKey publicKey) {
        // Parse the JWS and verify its RSA signature
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }

    @Test
    void testSignAndVerify() throws Exception {
        Date now = new Date();

        JWSSigner signer = new RSASSASigner(privateKeyfromString(PRIVATE_KEY));

// Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("my-aud")
                .subject("my-sub")
                .claim("first", "David")
                .claim("last", "Hay")
                .issueTime(now)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                claimsSet);

// Compute the RSA signature
        signedJWT.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String jwtToken = signedJWT.serialize();

        SignedJWT signedJWT2 = SignedJWT.parse(jwtToken);
        JWSVerifier verifier = new RSASSAVerifier(publicKeyfromString(PUBLIC_KEY));
        assertTrue(signedJWT2.verify(verifier));

        JWTClaimsSet claimSet = signedJWT2.getJWTClaimsSet();
        assertEquals(claimSet.getAudience(), List.of("my-aud"));
        assertEquals(claimSet.getSubject(), "my-sub");
        assertEquals(claimSet.getClaim("first"), "David");
        assertEquals(claimSet.getClaim("last"), "Hay");
        assertEquals(claimSet.getIssueTime().toInstant(), Instant.ofEpochSecond(now.getTime() / 1000));
    }
}
