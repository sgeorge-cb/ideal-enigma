package org.caringbridge.client.security.repository;

import java.util.List;

import org.caringbridge.client.security.model.Profile;
import org.springframework.data.repository.CrudRepository;

public interface ProfileRepository extends CrudRepository<Profile, Integer> {
	   
    public List<Profile> findByEmailAddress(String emailAddress);  
}
