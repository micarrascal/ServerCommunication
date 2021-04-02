import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Criptografia {
	
	private final static String ALGORITMO = "RSA";
	
	public static String printHexBinary(byte[] certificadoEnBytes) {
		return DatatypeConverter.printHexBinary(certificadoEnBytes);
		
	}
	
	

}