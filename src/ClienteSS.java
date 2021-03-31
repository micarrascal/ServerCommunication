import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class ClienteSS {
	
	private PrintWriter out = null;					//escritura en soket
	private BufferedReader in = null;				//lectura en soket
	private Socket server = null;					//soket del servidor
	private int id;
	
	

	public ClienteSS(String pServidorNombre, int pPuerto) throws UnknownHostException, IOException {
		this.server = new Socket( pServidorNombre, pPuerto );
		out = new PrintWriter(server.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader( server.getInputStream()));
		id = 0 + (int)(Math.random() * 100);
	}
	
	public int getId() {
		return id;
	}

