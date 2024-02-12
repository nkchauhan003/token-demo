package com.cb.jwt;

import com.cb.util.CbConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class JwtToken {
    private static final Key HMAC_KEY = new SecretKeySpec(Base64.getDecoder().decode("asdfSFS34wfsdfsdfSDSD32dfsddDDerQSNCK34SOWEK5354fdgdf4"),
            SignatureAlgorithm.HS256.getJcaName());

    public static String createJWTs(String data) {
        String jwtToken = Jwts.builder()
                .claim("data", CbConstants.DATA)
                .signWith(HMAC_KEY)
                .compact();
        return jwtToken;
    }

    public static String parseJWTs(String token) {


        Jws<Claims> jwt = Jwts.parser()
                .setSigningKey(HMAC_KEY)
                .build()
                .parseClaimsJws(token);

        return jwt.toString();
    }

    public static void main(String[] args) {
        System.out.println("Creating jwt ...");
        var token = createJWTs(CbConstants.DATA);
        System.out.println("Token: " + token);
        System.out.println("Parsing jwt ...");
        var data = parseJWTs(token);
        System.out.println("Date: " + data);

    }
}
