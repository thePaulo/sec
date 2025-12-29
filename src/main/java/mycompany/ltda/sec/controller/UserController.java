package mycompany.ltda.sec.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class UserController {

    @RequestMapping("/")
    public ResponseEntity<Object> getRequisicoes(Principal principal){//ResponseEntity<Void>
        System.out.println(principal);
        System.out.println("test");
        //return ResponseEntity.ok().build();
        //return "redirect:http://www.google.com";
        return new ResponseEntity<>("http://www.google.com", HttpStatus.OK);
    }
}
