import java.io.*;
import java.net.*;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class project3 {
    final protected static char[] HEX_ARRAY = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public static final int BLOCK_SIZE = 16;
    public static final String CIPHER_TEXT = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";
    public static final String URL = "http://crypto-class.appspot.com/po?er=";

    public static void main(String[] args) throws IOException, Exception {
        //ciphertext in bytes
        byte[] c = hexStringToByteArray(CIPHER_TEXT);
        String dec = "";
        for (int block = 0; block < (c.length - BLOCK_SIZE) / BLOCK_SIZE; block++) {
            
            byte[] cb = Arrays.copyOfRange(c, 0, c.length - block * BLOCK_SIZE);

            for (int i = 0; i < BLOCK_SIZE; i++) {

                byte[] cm = cb.clone();
                byte found = 0;

                int pos = cb.length - 1 - BLOCK_SIZE - i;

                // PLAINTEXT
                for (int b = 0; b < 256; b++) {

                    // pad
                    for (int k = 0; k < i + 1; k++) {
                        cm[pos + k] = (byte) (cb[pos + k] ^ (i + 1));
                    }

                    // xor
                    cm[pos] = (byte) (cm[pos] ^ b);

                    int status = getUrlStatus(URL + byteArrayToHexString(cm));

                   
                    

                    System.out.println("[ Block number : " + (block+1) + " ] [ Guess Bytes : " + b + " ] [ error : " + status + " ] = " + byteArrayToHexString(cm));


                    if (status == 404) {
                        // if pad is correct : error 404
                        found = (byte) b;
                        break;
                    } else if (status == 200) {
                        // if 404 error not found 
                        // error 200 is the next option
                        found = (byte) b;
                    }
                }

              
                cb[pos] = (byte) (cb[pos] ^ found);

                // ASCII
                dec = (char) found + dec;

                System.out.println("found : " + found + " = " + dec);
                System.out.println();
            }
        }
        
        
        // create 2 new keys for Erypted-then-Mac
        String k1 = makeKey();
        String k2 = makeKey();
        

        System.out.println("Encryption key : " + k1);
        System.out.println("Authorisation key : " + k2);
        System.out.println("Plaintext : " + dec);
        // AuthenticatedEncryption for Encrypted-then-Mac
        AuthenticatedEncryption authenticatedEncryption = new AuthenticatedEncryption(k1, k2);
        String encrypted = authenticatedEncryption.encrypt(dec);
        System.out.println("Authenticated and encrypted Plaintext: " + encrypted);

        
        String hack_key = makeKey();
        AuthenticatedEncryption authenticatedEncryption1 = new AuthenticatedEncryption(k1, hack_key);
        String decrypted1 = authenticatedEncryption1.decrypt(encrypted);
        System.out.println("Decrypted with wrong auth_key: " + decrypted1);
    }

    public static int getUrlStatus(String urlPath) throws IOException {
        URL url = new URL(urlPath);
        URLConnection connection = url.openConnection();

        connection.connect();

        if (connection instanceof HttpURLConnection) {
            HttpURLConnection httpConnection = (HttpURLConnection) connection;

            return httpConnection.getResponseCode();
        } else {
            return 0;
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), BLOCK_SIZE) << 4)
                    + Character.digit(s.charAt(i + 1), BLOCK_SIZE));
        }
        return data;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    private static String makeKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] secretKeyEncoded = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(secretKeyEncoded);
}
}
