package com.ealanta.jwt.jsonwebtoken;


import com.ealanta.jwt.BaseJWTTest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JWTSignThenVerifyTest extends BaseJWTTest {

    @Test
    @Disabled
    void testGenerateKey() throws Exception {

        RSAPrivateKey privateKey = (RSAPrivateKey) null;
        assertEquals("PKCS#8", privateKey.getFormat());
        RSAPublicKey publicKey = (RSAPublicKey) null;
        assertEquals("X.509", publicKey.getFormat());
        assertEquals(privateKey.getModulus(), publicKey.getModulus());
    }
    @Override
    public boolean isSignatureValid(String jwtToken, RSAPublicKey publicKey) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(jwtToken);
            assertEquals(claims.getBody().getSubject(), "1234567890");
            assertEquals(claims.getBody().get("name", String.class), "David Hay");
            assertEquals(claims.getBody().get("admin", Boolean.class), true);
            assertEquals(claims.getBody().getIssuedAt().toInstant(), Instant.ofEpochSecond(1516239022L));
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
        return true;
    }

    @Test
    void testSignAndVerify() throws Exception {
        Map<String, Object> claimsIN = Map.of("first", "David", "last", "Hay");
        Date now = new Date();
        String jwtToken = Jwts.builder()
                .setIssuedAt(now)
                .setSubject("my-sub")
                .setAudience("my-aud")
                .addClaims(claimsIN)
                .signWith(privateKeyfromString(PRIVATE_KEY)).compact();

        Jws<Claims> claimsOUT = Jwts.parserBuilder().setSigningKey(publicKeyfromBase64String(BASE64_ENCODED_PUBLIC_KEY)).build().parseClaimsJws(jwtToken);
        assertEquals(claimsOUT.getBody().getAudience(), "my-aud");
        assertEquals(claimsOUT.getBody().getSubject(), "my-sub");
        assertEquals(claimsOUT.getBody().get("first", String.class), "David");
        assertEquals(claimsOUT.getBody().get("last", String.class), "Hay");
        assertEquals(claimsOUT.getBody().getIssuedAt().toInstant(), Instant.ofEpochSecond(now.getTime() / 1000));
    }
}