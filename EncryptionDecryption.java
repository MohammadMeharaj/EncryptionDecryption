import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.security.Key;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class EncryptingFile {
    public static void main(String[] args)  {

        try {
            // Read a file
            Reader filereader = new FileReader("Encrypt.txt");
            BufferedReader b1 = new BufferedReader(filereader);
            String Line;
            StringBuilder contentBuilder = new StringBuilder();
            while ((Line = b1.readLine()) != null) {
                contentBuilder.append(Line);
            }
            String content = contentBuilder.toString().trim();
            System.out.println("Before encryption:\n" + content);
            System.out.println("Reading successfully completed");

            // Generate key
            KeyGenerator keygenerator=KeyGenerator.getInstance("AES");
            keygenerator.init(256);
            SecretKey secretKey = keygenerator.generateKey();
            // Encrypt the file
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] input = content.getBytes();
            byte[] cipherText = cipher.doFinal(input);//completes encrypt process
            String result = Base64.getEncoder().encodeToString(cipherText);

            System.out.println("Encrypted text: " + result);

            // Save the encrypted text to a file
            FileWriter w1 = new FileWriter("Encrypt11.txt");
            w1.write(result);
            w1.close();

            // Decrypt the file
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(result));
            String originalText = new String(decryptedText);
            System.out.println("Decrypted text: " + originalText);

        } catch (Exception e) {
           System.out.println("Error");
        }
    }
}

