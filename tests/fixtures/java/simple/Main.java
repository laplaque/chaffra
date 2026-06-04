package com.example;

import com.example.utils.StringUtils;

public class Main {
    public static void main(String[] args) {
        String greeting = StringUtils.greet("world");
        System.out.println(greeting);
    }

    private static void unusedMethod() {
        System.out.println("never called");
    }
}
