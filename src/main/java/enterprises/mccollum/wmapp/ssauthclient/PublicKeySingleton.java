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

import enterprises.mccollum.wmapp.authobjects.AuthConstants;

@Singleton
@Startup
public class PublicKeySingleton {
	
	PublicKey pubKey = null;
	
	@PostConstruct
	public void fetchPubKey(){
		
		try {
			FileInputStream is = new FileInputStream(AuthConstants.keyStorePath);
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(is, null);
			Certificate cert = keystore.getCertificate(AuthConstants.pubKeyAlias);
			pubKey = cert.getPublicKey();	
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Lock(LockType.READ)
	public PublicKey getPublicKey(){
		return pubKey;
	}
}
