package mycompany.ltda.sec.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class UserController {

    @RequestMapping("/")
    public String getRequisicoes(Principal principal){
        System.out.println(principal);
        System.out.println("entrou");
        return "haha";
    }
}
