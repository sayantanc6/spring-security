package dummy.security;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import dummy.config.RsaKeyProperties;
import dummy.entity.ProductUser;

@Service
public class JWTService {
	
	@Autowired
	RsaKeyProperties prop;
	
	JWSSigner signer;
	
	SignedJWT signedJWT;

	public String generateToken(ProductUser produser){
		String token =null;
		try {
			String scope = produser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
			
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
						                .issuer("self") 
						                .issueTime(Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC))) 
						                .expirationTime(Date.from(LocalDateTime.now().plusHours(1).toInstant(ZoneOffset.UTC)))  
						                .subject(produser.getUsername())
						                .claim("scope", scope).build();
			
			/* All Auth0-issued JWTs have JSON Web Signatures (JWSs), meaning they are signed rather than encrypted. 
			 * A JWS represents content secured with digital signatures or Message Authentication Codes (MACs) using JSON-based data structures.
			 * JWS is used to validate that the token is trustworthy and has not been tampered with. 
			 * When you use a JWT, you must check its signature before storing and using it.
			 */
			this.signer = new RSASSASigner(prop.getPrivateKey());
			this.signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);  
					
			this.signedJWT.sign(signer);
			token = this.signedJWT.serialize();
		} catch (JOSEException e) {
			e.printStackTrace();
		}
        
        return token;
	}
	
	public String getUsernameByToken(String token) { 
		String username=null;
		
		try {
			username = SignedJWT.parse(token).getJWTClaimsSet().getSubject();
		} catch (ParseException e) {
			System.out.println("extract username exception : "+e);
		}
		return username;
	} 
	  
	public Boolean isTokenExpired(String token) {
		Boolean tokenExpired=false; 
			
		try {
			tokenExpired = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime().before(new Date());
		} catch (NumberFormatException | ParseException e) {
			System.out.println("number format exception or parse exception : "+e);
		}
		
		return tokenExpired;
	}
	  
	public Boolean isTokenValid(String token) {
		 
		return (!isTokenExpired(token) && isSignatureValid(token));
	}
	
	public Boolean isSignatureValid(String token) {
		Boolean signatureValid = false;
	    
	    try {
    		signatureValid = SignedJWT.parse(token).verify(new RSASSAVerifier(prop.getPublicKey()));
	    } catch (ParseException | JOSEException e) {
			System.out.println("signature invalid for this token : "+e);
	    }
	    return signatureValid;
	}
        }
