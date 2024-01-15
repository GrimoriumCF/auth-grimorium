package br.com.grimorium.authms.exception;

public class UsernameExistException extends Exception {
    public UsernameExistException(String format) {
        super(format);
    }
}
