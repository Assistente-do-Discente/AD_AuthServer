package br.assistentediscente.authserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/info")
public class LegalInfo {

    @GetMapping("/terms")
    public String terms(){
        return "terms";
    }


    @GetMapping("/policy")
    public String policy(){
        return "policy";
    }
}
