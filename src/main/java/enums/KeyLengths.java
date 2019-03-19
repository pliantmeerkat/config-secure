package enums;

public enum KeyLengths {

    FOUR(4),
    EIGHT(8),
    SIXTEEN(16),
    THIRTY_TWO(32),
    SIXTY_FOUR(64),
    ONE_TWO_EIGHT(128),
    TWO_FIVE_SIX(256);


    private int value;

    KeyLengths(int value) {
        this.value = value;
    }

    public int toInt() {
        return this.value;
    }
}
