import java.awt.List;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

public class Certificados {
	
	private static String[] ALGORITMOS = (String[]) (Arrays.asList("SHA256withRSA", "SHA1withRSA", "SHA224withRSA", "SHA384withRSA", "SHA512withRSA")).toArray();
	
	public static X509Certificate generarCertificado(KeyPair  keyPair) throws CertificateException, OperatorCreationException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(ALGORITMOS[0]);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
        
		org.bouncycastle.asn1.x500.X500Name emisor = new X500Name("CN=Test, L=London, C=GB");
		BigInteger serial = new BigInteger(64, new SecureRandom());
		Date notBefore = new Date(2019, 01, 01);
		System.out.println("Generado certificado: fecha de emicion: " + notBefore.toString());
		Date notAfter = new Date(2020, 01 ,01);

		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		
		System.out.println("Generado certificado: fecha de expiracion: " + notAfter .toString());
		X509v3CertificateBuilder b = new X509v3CertificateBuilder(emisor, serial, notBefore, notAfter, emisor, subPubKeyInfo);
		
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
		X509CertificateHolder certificateHolder = b.build(sigGen);
		
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
	}
	
	public static boolean verificarCertificado(X509Certificate certificado) {
		try {
			certificado.checkValidity();
			certificado.verify(certificado.getPublicKey());
			return true;
		} catch (Exception e) {
			return false;
		}
	}
}
