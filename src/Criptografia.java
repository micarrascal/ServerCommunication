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
	
    public KeyPair generadorLLaves() throws NoSuchAlgorithmException {
		//Generacion de claves
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
		generator.initialize(1024);
		return generator.generateKeyPair();
	}
	
	public SecretKey generadorLLave128() throws NoSuchAlgorithmException {
		//Generacion de clave SecretKey
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128);
		return generator.generateKey();
	}
	
	
	public static byte[] cifrarAsimetrico(Key llave, String texto){
		 byte[] textoCifrado;
		 
		 try {
			 Cipher cifrador = Cipher.getInstance(ALGORITMO);
			 byte[] textoClaro = texto.getBytes();
			 
			 cifrador.init(Cipher.ENCRYPT_MODE, llave);
			 textoCifrado = cifrador.doFinal(textoClaro);
			 
			 return textoCifrado;
		 }catch(Exception e) {
			 System.out.println("Exception: " + e.getMessage());
			 return null;
		 }
	}
	
	public static byte[] descifrarAsimetrico(Key llave, byte[] texto){
		byte[] textoClaro;
		
		try {
			Cipher cifrador = Cipher.getInstance(ALGORITMO);
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrador.doFinal(texto);
		}catch(Exception e) {
			System.out.println("Exception: "+ e.getMessage());
			return null;
		}
		return textoClaro;
	}
	
	public static byte[] cifrarSimetrico(Key llave, String texto) {
		try {
			Cipher cifrador = Cipher.getInstance("AES");
			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			return cifrador.doFinal(texto.getBytes());
		} catch (Exception e) {
			System.out.println("Exception: "+ e.getMessage());
			return null;
		}
	}
	
	public static byte[] descifrarSimetrico(Key llave, byte[] texto) {
		try {
			Cipher cifrador = Cipher.getInstance("AES");
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			return cifrador.doFinal(texto);
		} catch (Exception e) {
			System.out.println("Exception: "+ e.getMessage());
			return null;
		}
	}
	

	



}