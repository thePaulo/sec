package mycompany.ltda.sec.domain;

public enum Role {

    ADMIN("admin"),
    USER("user");

    String role;

    Role(String role){
        this.role = role;
    }

    public String getRole(){
        return role;
    }
}
