import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;

public class ClienteCS {
	private PrintWriter out = null;					//escritura en soket
	private BufferedReader in = null;				//lectura en soket
	private Socket server = null;					//soket del servidor
	private int id;
	
	

	public ClienteCS(String pServidorNombre, int pPuerto) throws UnknownHostException, IOException {
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
		ClienteCS client;
		try {
//			System.out.println("----------------------------------\nInicializado cliente ... \n----------------------------------");
//			//inicializacion del cliente
//			System.out.println("Por favor ingrese el puerto de conexion");
//			Scanner consola  = new Scanner(System.in);
//			int puerto = consola.nextInt();
//			System.out.println("Por favor ingrese el host de conexion");
//			String host = consola.next();
			
			client = new ClienteCS("localhost", 44);
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
			
			Key KeyServidor = certificadoServidorC.getPublicKey();
			
			Key keySimetrica = criptografia.generadorLLave128();
			
			byte[] sobre = criptografia.cifrarAsimetrico(KeyServidor, new String(keySimetrica.getEncoded()));

			String sobreString = new String (criptografia.printHexBinary(sobre));
			
			byte[] sobreServidor = DatatypeConverter.parseHexBinary(client.enviarAServidor(sobreString));
			
			//intercambio de llave simetricas
			
			String contenido = criptografia.printHexBinary(criptografia.descifrarAsimetrico(keyPair.getPrivate(), sobreServidor));
			
			
			//System.out.println(DatatypeConverter.parseHexBinary(contenido));
			String pk = criptografia.printHexBinary(keySimetrica.getEncoded());
			if(!contenido.equals(pk)) {
				client.enviarMensajeSinRespuesta("ERROR");
				client.close();
				System.err.println("ERROR en intercambio de llaves");
				System.exit(1);
			}
				
			client.enviarMensajeSinRespuesta("OK");
			
			System.out.println("----------------------------------\nValidacion intercambio de llave simetrica OK...\n----------------------------------");
			String coordenadas = client.getId() + ";" + (int)(Math.random() * 90 ) + ".00," + (int)(Math.random() * 100) + ".01";
			client.enviarMensajeSinRespuesta(criptografia.printHexBinary(criptografia.cifrarSimetrico(keySimetrica, coordenadas)));
			String hmac = criptografia.printHexBinary(criptografia.generarHmac(keySimetrica, coordenadas));
			String respuesta = criptografia.printHexBinary(criptografia.descifrarAsimetrico(KeyServidor, DatatypeConverter.parseHexBinary(client.enviarAServidor(hmac))));

			if(!respuesta.equals(hmac)) {
				System.err.println("ERROR HMAC no valido");
			}
			
			System.out.println("----------------------------------\nTermino de protocolo exitoso...\n----------------------------------");
			client.close();

		} catch( Exception e ) {
			e.printStackTrace();
			System.exit(1);
		}
	}
}