package enterprises.mccollum.ssauthclient;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.inject.Inject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import enterprises.mccollum.wmapp.ssauthclient.PublicKeySingleton;
import enterprises.mccollum.wmapp.ssauthclient.SSAuthClient;

/**
 * Read JWTs into their real token classes and verify their signatures
 * 
 * @author smccollum
 */
@Local
@Stateless
public class JWTReaderUtils {
	public static final String SIGNATURE_TYPE="SHA256withRSA";
	public static final Charset DECODE_CHARSET = StandardCharsets.UTF_8;
	
	@Inject
	PublicKeySingleton pks;
	
	final Gson gsonWithExclusions;
	final Gson gson;
	
	final int HEADER_SEGMENT = 0;
	final int PAYLOAD_SEGMENT = 1;
	final int SIGNATURE_SEGMENT = 2;
	
	public JWTReaderUtils(){
		gsonWithExclusions = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
		gson = new Gson();
	}
	
	private boolean validateSignature(byte[] headerPayloadBin, byte[] signature){
		try{
			Signature verifier = Signature.getInstance(SIGNATURE_TYPE);
			verifier.initVerify(pks.getPublicKey());
			verifier.update(headerPayloadBin);
			return verifier.verify(signature); //returns true if verification is successful
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}
	
	/**
	 * Verify the JWT signature and return as an instantiated class using gson if successful
	 * 
	 * @param jwtString: Json Web Token String to verify
	 * @param tokenClass: The class packed inside the JWT
	 * @param <T> The type of the token class in the JWT
	 * @param useExclusions: whether or not to exclude fields not annotates with @Expose
	 * 
	 * @return the class if it could be verified and null if not
	 */
	public <T> T verifyJwt(String jwtString, Class<T> tokenClass, boolean useExclusions){
		String[] components = jwtString.split("\\.");
		if(components.length != 3){
			System.out.println("Incorrect number of parts: "+components.length);
			return null;
		}
		/**
		 * Determine where to split the signature from the header/payload portion for signature verification
		 */
		int indexOfSignatureSplit = jwtString.lastIndexOf('.');
		String headerPayload = jwtString.substring(0, indexOfSignatureSplit);
		byte[] headerPayloadBin = headerPayload.getBytes(DECODE_CHARSET);
		if(!validateSignature(headerPayloadBin, Base64.getUrlDecoder().decode(components[SIGNATURE_SEGMENT]) )){
			System.out.println("Couldn't validate signature using: "+SSAuthClient.authServerUrl);
			return null;
		}
		/**
		 * Decode the json into the appropriate class
		 */
		return (useExclusions ? gsonWithExclusions : gson).fromJson(
					new String(Base64.getUrlDecoder().decode(components[PAYLOAD_SEGMENT]),
				DECODE_CHARSET), tokenClass);
	}
}
