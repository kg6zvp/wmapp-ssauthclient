package enterprises.mccollum.wmapp.ssauthclient;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
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
import javax.ejb.Startup;
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
@Startup
public class PublicKeySingleton {
	/**
	 * This key will contain the public and private keys used to sign content for auth
	 */
	PublicKey pubKey;
	
	public String keystorePath;
	private static final char[] KEYSTORE_PASS = "password".toCharArray();
	
	public static final String KEY_ALIAS = "WMAUTH";
	//private static final char[] KEY_PASS = "password".toCharArray();

	private static final String AUTH_SERVER_PUBKEY_URL = "http://auth.wmapp.mccollum.enterprises/api/key/getPubKey";
	
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
		keystorePath = null;
		if(keystorePath != null){ //if the keystore can be read
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
				//TODO: fallback to reading pem file
			}
		}
		return null;
	}
	
	private PemObject ldPemFromServer() {
		Client c = ClientBuilder.newClient();
		String pemString = c.target(AUTH_SERVER_PUBKEY_URL).request().get(String.class);
		@SuppressWarnings("resource") //It's clearly being used
		PemReader pemReader = new PemReader(new StringReader(pemString));
		try {
			return pemReader.readPemObject();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private KeyStore readKeyStore(String ksPath) throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(ksPath), KEYSTORE_PASS);
		return ks;
	}
}
