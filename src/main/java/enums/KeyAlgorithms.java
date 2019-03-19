package enums;

/**
 * <h1>KeyAlgorithms</h1>
 * <p>Enum to be used to set the encryption manager key generation algorithm</p>
 *
 * @author JackBranch
 */
public enum KeyAlgorithms {
    PBKDF("PBKDF2WithHmacSHA512");

    private String value;

    KeyAlgorithms(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }
}
