import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;


public class Main {
    public static void main(String[] args) throws Exception {
        String mensagemOriginal = "Michel";

        KeyPair keyPair = geraRSAKeyPair();

        System.out.println("A mensagem original é :" + mensagemOriginal);

        byte[] mensagemCifrada = encripta(mensagemOriginal, keyPair.getPublic());

        System.out.println("A mensagem cifrada é :" + HexFormat.of().formatHex(mensagemCifrada));

        String mensagemRecuperada = decripta(mensagemCifrada, keyPair.getPrivate());

        System.out.println("A mensagem recuperada é :" + mensagemRecuperada);

    }
    public static KeyPair geraRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(512);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        System.out.println("----------------------------------------------------------------------");

        System.out.println("PUBLIC hex: "+ HexFormat.of().formatHex(keyPair.getPublic().getEncoded()));
        System.out.println("PRIVATE hex: "+ HexFormat.of().formatHex(keyPair.getPrivate().getEncoded()));

        System.out.println("----------------------------------------------------------------------");

        System.out.println("PUBLIC base64: "+ Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("PRIVATE base64: "+ Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        System.out.println("----------------------------------------------------------------------");


        return keyPair;
    }

    public static byte[] encripta(String mensagem, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(mensagem.getBytes(StandardCharsets.UTF_8));
    }

    public static String decripta(byte[] mensagemCifrada, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] mensagemAberta = cipher.doFinal(mensagemCifrada);

        return new String(mensagemAberta);
    }
}