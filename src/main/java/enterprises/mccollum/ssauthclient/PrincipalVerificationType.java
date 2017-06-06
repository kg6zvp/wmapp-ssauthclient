package enterprises.mccollum.ssauthclient;

/**
 * Used to specify mode of authentication/user identity verification for performing custom behavior
 * 
 * @author smccollum
 */
public enum PrincipalVerificationType {
	/**
	 * Used to specify user verification through session variable
	 */
	SESSION,
	/**
	 * Used to specify user verification through a cookie
	 */
	COOKIE,
	/**
	 * Used to specify user verification through an authorization header (OAuth)
	 */
	AUTHORIZATION_HEADER,
	/**
	 * Used to specify that the token was passed explicitly in the header
	 */
	TOKEN_HEADER,
	/**
	 * Used to specify that the token was passed as the URL parameter 'token' (OAuth)
	 */
	URL_PARAM,
	/**
	 * Used to specify that the token was passed with the 'code' URL parameter (OAuth)
	 */
	CODE_PARAM;
}
