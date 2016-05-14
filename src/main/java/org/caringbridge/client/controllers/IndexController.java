package org.caringbridge.client.controllers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.caringbridge.client.security.services.SAMLGeneratorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class IndexController {

	@Autowired
	SAMLGeneratorService samlService;
	
    @RequestMapping(value={"", "/", "/login","/error"},method={RequestMethod.POST,RequestMethod.GET})
    public String home() {
        return "login";
    }

    @RequestMapping(value={"/goto/{pageName}"},method={RequestMethod.POST,RequestMethod.GET})
    public String goToPage(@PathVariable(value="pageName") final String pageName) {
        return pageName;
    }

    @RequestMapping(value="/saml",method=RequestMethod.GET,produces="text/html")
    public String redirect(Model model) {
    	try {
    		model.addAttribute("spPostUrl", "http://localhost:8080/consume.jsp");
    		model.addAttribute("sAMLResponse",samlService.getSamlResponse(
    				SecurityContextHolder.getContext().getAuthentication().getName()));
        	return "saml";
    	} catch (Exception e) {
			e.printStackTrace();
		} 
    	return "error";
    }
    
    @RequestMapping(value="/logout", method = RequestMethod.GET)
    public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){    
            new SecurityContextLogoutHandler().logout(request, response, auth);
            new CookieClearingLogoutHandler("JSESSIONID","rem-cookie").logout(request, response, auth);
        }
        return "redirect:/login?logout";
    }

}
