package enterprises.mccollum.ssauthclient;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 * This class is responsible for encoding and decoding request state information into URLs
 * @author smccollum
 */
@Local
@Stateless//*/
public class URLStateUtils {
	static final Charset CHARSET = StandardCharsets.UTF_8;
	
	@Inject
	URLContextUtils urlCtxUtils;
	
	public URLStateUtils(){}
	
	/**
	 * Encodes the given request URL and parameters into a base64 string which can be passed as a single parameter
	 * @param req
	 * @return
	 */
	public String encodeRequestUrlToParam(HttpServletRequest req){
		//StringBuilder urlBuilder = new StringBuilder(req.getRequestURL());
		String requestUri = req.getRequestURI().replace(req.getContextPath(), "");
		StringBuilder urlBuilder = new StringBuilder(urlCtxUtils.getApplicationBaseUrl(req)+requestUri);
		if(req.getQueryString() != null)
			urlBuilder.append("?"+req.getQueryString());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(urlBuilder.toString().getBytes(CHARSET));
	}
	
	/**
	 * Decodes the base64 string parameter into the original request url so that the user can be redirected or whatever
	 * @param param
	 * @return
	 */
	public String decodeUrlStateToRequestUrl(String param){
		return new String(Base64.getUrlDecoder().decode(param), CHARSET);
	}
}
