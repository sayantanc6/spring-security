package dummy.utility;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.springframework.stereotype.Component;

@Component
public class KeyGeneratorUtility {
	
	public KeyPair generateKey() {
		
        KeyPair keyPair;

        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch(Exception e){
            throw new IllegalStateException();
        }

        return keyPair;
	}
	/*
	public void generateKeyStoreFile() {
		
		 try {
			 String command = "keytool -genkeypair -alias springboot -keyalg RSA -keysize 4096 -storetype JKS -keystore springboot.jks -validity 3650 -storepass password";
			 ProcessBuilder pb = new ProcessBuilder("cmd.exe");
			 Process process = pb.start();
			 PrintWriter commandWriter = new PrintWriter(new OutputStreamWriter(new BufferedOutputStream(process.getOutputStream())));
			 commandWriter.println(command);
			 commandWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	*/
}
