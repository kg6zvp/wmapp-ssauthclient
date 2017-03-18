package enterprises.mccollum.wmapp.ssauthclient;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.annotation.PostConstruct;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;


@Singleton
@Startup
public class PublicKeySingleton {
	/**
	 * This key will contain the public and private keys used to sign content for auth
	 */
	PublicKey pubKey;
	
	public static final String KEYSTORE_PATH = "/home/smccollum/wmks.jks";
	private static final char[] KEYSTORE_PASS = "password".toCharArray();
	
	public static final String KEY_ALIAS = "WMAUTH";
	//private static final char[] KEY_PASS = "password".toCharArray();
	
	@PostConstruct
	public void init(){
		try {
			pubKey = loadPubKey();
		} catch (Exception e) {
			System.out.print("Honestly, I'm just sick of this at this point. I've been coding for hours trying to eliminate errors and this is what happens. I don't know what went wrong. Try checking line 44 of the file CryptoSingleton.java to see what's up here.\n");
			e.printStackTrace();
		}
	}
	
	@Lock(LockType.READ)
	public PublicKey getPublicKey(){
		return pubKey;
	}
	
	private PublicKey loadPubKey() throws Exception{
		KeyStore ks = readKeyStore(KEYSTORE_PATH);
		Certificate cer = ks.getCertificate(KEY_ALIAS); //get public key, part I
		return cer.getPublicKey();
	}
	
	private KeyStore readKeyStore(String ksPath) throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(ksPath), KEYSTORE_PASS);
		return ks;
	}
}
