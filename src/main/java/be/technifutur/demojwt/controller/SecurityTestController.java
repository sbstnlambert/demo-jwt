package be.technifutur.demojwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/security")
public class SecurityTestController {

    @PreAuthorize("isAuthenticated()") // Security constraint: User has to be identified
    @GetMapping("/authenticated")
    public String getConnected() {
        return "connected";
    }
}
