package enterprises.mccollum.wmapp.ssauthclient;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

import enterprises.mccollum.wmapp.authobjects.AuthConstants;

public class AuthRequestFilter implements ContainerRequestFilter{

	@Inject
	PublicKeySingleton pks;
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		//TODO Auto-generated method 
		String userTokenCt = requestContext.getHeaderString(AuthConstants.USER_TOKEN_HEADER);
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, (RSAPublicKey) pks.getPublicKey());
			byte[] verifiedToken = cipher.doFinal(userTokenCt.getBytes("UTF8"));
			byte[] readableToken = (new Base64.Encoder()).encode(verifiedToken);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	

}
