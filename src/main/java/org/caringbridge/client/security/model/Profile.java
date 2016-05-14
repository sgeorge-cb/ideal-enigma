package org.caringbridge.client.security.model;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Field;

public class Profile {
	
        @Id
	@Field("_id")
	private Integer profileId;
	private String firstName;
	private String lastName;
	private Email email;
	private String guid;
	private String password;
	
	//Todo - Future need to update as soon as we login
	private LocalDateTime lastLoginDateTime;
	//Todo - Need to update if the login attempt failed
	private Integer failedLoginAttempts;
	
	// Getters and Setters
	public Integer getProfileId() {
		return profileId;
	}
	public void setProfileId(Integer profileId) {
		this.profileId = profileId;
	}
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public Email getEmail() {
		return email;
	}
	public void setEmail(Email email) {
		this.email = email;
	}
	public static class Email {
		private String address;

		public String getAddress() {
			return address;
		}
		public void setAddress(String address) {
			this.address = address;
		}
	}
	
	public String getGuid() {
	    return guid;
	}
	public void setGuid(String guid) {
	    this.guid = guid;
	}

	public String getPassword() {
	    return password;
	}
	public void setPassword(String password) {
	    this.password = password;
	}
	public LocalDateTime getLastLoginDateTime() {
	    return lastLoginDateTime;
	}
	public void setLastLoginDateTime(LocalDateTime lastLoginDateTime) {
	    this.lastLoginDateTime = lastLoginDateTime;
	}
	public Integer getFailedLoginAttempts() {
	    return failedLoginAttempts;
	}
	public void setFailedLoginAttempts(Integer failedLoginAttempts) {
	    this.failedLoginAttempts = failedLoginAttempts;
	}

}
