package org.caringbridge.client.security.services;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

@Service
public class BCryptUtility {
    
    	private static String getCompatibleHashVersion(String storedHash) {
    	    if(null == storedHash || !(storedHash.startsWith("$2y$") || storedHash.startsWith("$2a$")))
			throw new java.lang.IllegalArgumentException("Invalid hash provided for comparison");

    	    return storedHash.replace("$2y$", "$2a$");
    	}
    
	public static boolean checkPassword(String plainTextPassword, String storedHash) {
		boolean isAuthenticated = false;
		isAuthenticated = BCrypt.checkpw(plainTextPassword, storedHash);
		return isAuthenticated;
	}
	
	public static boolean authenticate(String plainTextPassword, String storedHash) {
	    return checkPassword(plainTextPassword, getCompatibleHashVersion(storedHash));
	    
	}
}
