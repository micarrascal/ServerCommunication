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

public String enviarAServidor(String pMensaje) throws IOException {
		out.println(pMensaje);
		System.out.println("Mensaje enviado		:	  " + pMensaje);
		String respuesta = in.readLine();
		System.out.println("Respuesta servidor	:	  " + respuesta);
		
		return respuesta;
	}
	
	public void enviarMensajeSinRespuesta(String pMensaje) throws IOException {
		out.println(pMensaje);	
		System.out.println("Mensaje enviado		:	  " + pMensaje);
	}
	
	public void inicilizarComunicacion() throws IOException {
		if(!enviarAServidor("HOLA").equals("OK"))
			System.err.println("ERROR respuesta no espereada: saludo");
		if(!enviarAServidor("ALGORITMOS:AES:RSA:HMACSHA1").equals("OK"))
			System.err.println("ERROR respuesta no espereada: algoritmos");
		
	}

	private void close() throws IOException {
		out.close();
		in.close();
		server.close();
	}

	
	public static void main(String[] args) {
		ClienteSS client;
		try {
			System.out.println("----------------------------------\nInicializado cliente ... \n----------------------------------");
			//inicializacion del cliente
			System.out.println("Por favor ingrese el puerto de conexion");
			Scanner consola  = new Scanner(System.in);
			int puerto = consola.nextInt();
			System.out.println("Por favor ingrese el host de conexion");
			String host = consola.next();
			
			client = new ClienteSS(host, puerto);
			client.inicilizarComunicacion();
			
			System.out.println("----------------------------------\nCliente inicializado con exito ... \n----------------------------------");

			//Inicia intercambio de certificados
			Certificados certificados  = new Certificados();
			Criptografia criptografia = new Criptografia();
			
			KeyPair keyPair = criptografia.generadorLLaves();
			X509Certificate certificadoCliente = certificados.generarCertificado(keyPair);
			
			byte[] certificadoClienteEnBytes = certificadoCliente.getEncoded( );
			
			String certificadoEnString = criptografia.printHexBinary(certificadoClienteEnBytes);
			
			String certificadoServidor = client.enviarAServidor(certificadoEnString);
			byte[] certificadoServidorEnBytes = DatatypeConverter.parseHexBinary(certificadoServidor);
			
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			InputStream input = new ByteArrayInputStream(certificadoServidorEnBytes);
			X509Certificate certificadoServidorC = (X509Certificate) cf.generateCertificate(input);
			
			if(!certificados.verificarCertificado(certificadoServidorC))
				System.err.println("ERROR certifiacado no valido");
			
			System.out.println("----------------------------------\nTerminada la validacion de certificado...\n----------------------------------");
			
			SecretKey keySimi = criptografia.generadorLLave128();
			String keyString = criptografia.printHexBinary(keySimi.getEncoded());
			
			
			if(!(client.enviarAServidor(keyString)).equals(keyString))
				System.err.println("ERROR la clave devuelta no coincide con la enviada");
			client.enviarMensajeSinRespuesta("OK");
			
			System.out.println("----------------------------------\nValidacion intercambio de llave simetrica...\n----------------------------------");
			String coordenadas = client.getId() + ";" + (int)(Math.random() * 90 ) + ".00," + (int)(Math.random() * 100) + ".01";
			client.enviarMensajeSinRespuesta(coordenadas);
			if(!client.enviarAServidor(coordenadas).equals(coordenadas))
				System.err.println("ERROR los datos retornados no coinciden con los enviados");
			System.out.println("----------------------------------\nTermrino de protocolo exitoso...\n----------------------------------");
			client.close();

		} catch( Exception e ) {
			e.printStackTrace();
			System.exit(1);
		}
	}
}