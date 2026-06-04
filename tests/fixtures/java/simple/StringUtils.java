package com.example.utils;

public class StringUtils {
    public static String greet(String name) {
        return "Hello, " + name + "!";
    }

    public static String formatName(String first, String last) {
        return first + " " + last;
    }

    private static String internalHelper() {
        return "internal";
    }
}
