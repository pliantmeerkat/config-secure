package exception;

/**
 * <h1>EncryptionManagerException</h1>
 * <p>Exception to be thrown  when errors in encryption manager occur</p>
 *
 * @author jackbranch
 */
public class EncryptionManagerException extends RuntimeException {

    public EncryptionManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
