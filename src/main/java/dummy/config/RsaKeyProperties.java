package dummy.config;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import dummy.utility.KeyGeneratorUtility;
import jakarta.annotation.PostConstruct;
import lombok.Data;

@Data
@Component
public class RsaKeyProperties {

	private RSAPrivateKey privateKey;
	
	private RSAPublicKey publicKey;
	
	@Autowired
	KeyGeneratorUtility keygen;

	@PostConstruct
	public void init() {
		KeyPair keyPair = keygen.generateKey();
		
		this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
		this.publicKey = (RSAPublicKey) keyPair.getPublic();
		
	//	keygen.generateKeyStoreFile();
	}
}
