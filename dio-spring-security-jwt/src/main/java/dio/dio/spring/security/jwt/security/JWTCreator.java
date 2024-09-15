package dio.dio.spring.security.jwt.security;

import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import java.security.Key;
import java.nio.charset.StandardCharsets;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JWTCreator {
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String ROLES_AUTHORITIES = "authorities";

    public static String create(String prefix, String key, JWTObject jwtObject) {
        String token = Jwts.builder().subject(jwtObject.getSubject()).issuedAt(jwtObject.getIssuedAt())
            .expiration(jwtObject.getExpiration()).claim(ROLES_AUTHORITIES, checkRoles(jwtObject.getRoles()))
            .signWith(getKey(key)).compact();
        return prefix + " " + token;
    }
    public static JWTObject create(String token, String prefix, String key)
            throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException {
        JWTObject object = new JWTObject();
        token = token.replace(prefix, "");
        token = token.replace(" ", "");
        Claims claims = Jwts.parser().verifyWith(getSecretKey(key)).build().parseSignedClaims(token).getPayload();
        object.setSubject(claims.getSubject());
        object.setExpiration(claims.getExpiration());
        object.setIssuedAt(claims.getIssuedAt());
        object.setRoles((List) claims.get(ROLES_AUTHORITIES));
        return object;

    }
    private static List<String> checkRoles(List<String> roles) {
        return roles.stream().map(s -> "ROLE_".concat(s.replaceAll("ROLE_",""))).collect(Collectors.toList());
    }
    private static Key getKey(String key)
    {
        byte[] keyBytes = Decoders.BASE64.decode(key);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    private static SecretKey getSecretKey(String key)
    {
        // SecretKey sk = Jwts.SIG.HS256.key().build();
        // byte[] rawData = sk.getEncoded();
        // String encodedString = Base64.getEncoder().encodeToString(rawData);
        // System.out.println(encodedString);
        byte[] keyBytes = Decoders.BASE64.decode(key);
        return Keys.hmacShaKeyFor(keyBytes);
    }











// import java.util.List;
// import java.util.stream.Collectors;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.ExpiredJwtException;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.MalformedJwtException;
// import io.jsonwebtoken.SignatureAlgorithm;
// import io.jsonwebtoken.SignatureException;
// import io.jsonwebtoken.UnsupportedJwtException;

// public class JWTCreator {
//     public static final String HEADER_AUTHORIZATION = "Authorization";
//     public static final String ROLES_AUTHORITIES = "authorities";

//     public static String create(String prefix,String key, JWTObject jwtObject) {
//         String token = Jwts.builder().setSubject(jwtObject.getSubject()).setIssuedAt(jwtObject.getIssuedAt()).setExpiration(jwtObject.getExpiration())
//                 .claim(ROLES_AUTHORITIES, checkRoles(jwtObject.getRoles())).signWith(SignatureAlgorithm.HS512, key).compact();
//         return prefix + " " + token;
//     }
//     public static JWTObject create(String token,String prefix,String key)
//             throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException {
//         JWTObject object = new JWTObject();
//         token = token.replace(prefix, "");
//         Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
//         object.setSubject(claims.getSubject());
//         object.setExpiration(claims.getExpiration());
//         object.setIssuedAt(claims.getIssuedAt());
//         object.setRoles((List) claims.get(ROLES_AUTHORITIES));
//         return object;

//     }
//     private static List<String> checkRoles(List<String> roles) {
//         return roles.stream().map(s -> "ROLE_".concat(s.replaceAll("ROLE_",""))).collect(Collectors.toList());
//     }


}