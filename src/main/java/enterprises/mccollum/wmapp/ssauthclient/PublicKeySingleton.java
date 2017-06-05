package enterprises.mccollum.wmapp.ssauthclient;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Tries to read the public key from a keystore file. If that fails, it falls back to reading the public key from the auth server
 * @author smccollum
 *
 */
@Singleton
public class PublicKeySingleton {
	/**
	 * This key will contain the public and private keys used to sign content for auth
	 */
	PublicKey pubKey;
	
	public String keystorePath;
	private static final char[] KEYSTORE_PASS = "password".toCharArray();
	
	public static final String KEY_ALIAS = "WMAUTH";
	//private static final char[] KEY_PASS = "password".toCharArray();

	private static final String AUTH_SERVER_URL_LOCAL = "http://localhost:8080/loginserver";
	private static final String AUTH_SERVER_URL_REMOTE = "http://wmapp.mccollum.enterprises/loginserver";
	
	private static final String PUBKEY_RELATIVE_URL = "/api/key/getPubKey";
	private static final String AUTH_SERVER_PUBKEY_URL_LOCAL = AUTH_SERVER_URL_LOCAL+PUBKEY_RELATIVE_URL;
	private static final String AUTH_SERVER_PUBKEY_URL_REMOTE = AUTH_SERVER_URL_REMOTE+PUBKEY_RELATIVE_URL;
	
	
	@PostConstruct
	public void init(){
		try {
			pubKey = loadPubKey();
			if(pubKey != null){
				Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, "Loaded publicKey successfully");
				return;
			}
		} catch (Exception e) {
			Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.SEVERE, "Honestly, I'm just sick of this at this point. I've been coding for hours trying to eliminate errors and this is what happens. I don't know what went wrong. Try checking line 61 of the file PublicKeySingleton.java to see what's up here.\n");
			e.printStackTrace();
		}
	}
	
	@Lock(LockType.READ)
	public PublicKey getPublicKey(){
		return pubKey;
	}
	
	private PublicKey loadPubKey() throws Exception{
		keystorePath = System.getenv("WMKS_PUBKEY_FILE");
		if(keystorePath != null && keystorePath.length() > 0){ //if the keystore can be read
			KeyStore ks = readKeyStore(keystorePath);
			Certificate cer = ks.getCertificate(KEY_ALIAS); //get public key, part I
			Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, "Read from "+keystorePath+" successfully");
			return cer.getPublicKey();
		}else{
			PemObject pemPubKey = ldPemFromServer();
			if(pemPubKey != null){
				KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
				PublicKey lPubKey =  kf.generatePublic(new X509EncodedKeySpec(pemPubKey.getContent()));
				Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, "Read public key from url successfully");
				return lPubKey;
			}else{
				//TODO: fallback to reading pem file (location not yet specified)
			}
		}
		return null;
	}
	
	private PemObject ldPemFromServer() {
		Client c = ClientBuilder.newClient();
		String pemString = null;
		if(canTargetLocal()){ //local login server
			SSAuthClient.authServerUrl = AUTH_SERVER_URL_LOCAL;
			Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, "Using localhost as login server");
			pemString = c.target(AUTH_SERVER_PUBKEY_URL_LOCAL).request().get(String.class);
		}else{ //remote login server
			SSAuthClient.authServerUrl = AUTH_SERVER_URL_REMOTE;
			Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, "Using remote server as login server");
			pemString = c.target(AUTH_SERVER_PUBKEY_URL_REMOTE).request().get(String.class);
		}
		@SuppressWarnings("resource") //It's clearly being used
		PemReader pemReader = new PemReader(new StringReader(pemString));
		try {
			return pemReader.readPemObject();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Tries to connect to itself a bunch of times and exits if it's not possible
	 * @return
	 */
	private boolean canTargetLocal() {
		HttpURLConnection con = null;
		try {
			con = (HttpURLConnection) new URL(AUTH_SERVER_PUBKEY_URL_LOCAL).openConnection();
		} catch (Exception e) {
			return false;
		}
		con.setConnectTimeout(500);
		try {
			con.connect();
		} catch (IOException e) {
			return false;
		}
		return true;
	}

	private KeyStore readKeyStore(String ksPath) throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(ksPath), KEYSTORE_PASS);
		return ks;
	}
}
