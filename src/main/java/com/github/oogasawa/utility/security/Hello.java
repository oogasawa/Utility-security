package com.github.oogasawa.utility.security;

public class Hello {

    static public void main(String[] args) {
        System.out.println("Direct Hello world!");
    }

    
    public void greetings(String message) {
        System.out.println(String.format("Hello %s!", message));
    }
    
}
