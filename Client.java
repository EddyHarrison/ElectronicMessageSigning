import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Client {
    String msg;
    byte[] byteKey;
    final String keyGeneration = "KEY_GENERATION";
    final String message = "MESSAGE";
    final int port = 1777;
    String str;
    String s = "3 лабораторная работа по защите информации";
    public Client(){
            msg = keyGeneration;
            try {
                connect(keyGeneration);
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
            msg = message;
            try {
                str = s;
                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(byteKey));
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE,privateKey);
                    msg = message+Base64.getEncoder()
                            .encodeToString(cipher
                                    .doFinal(str.getBytes(StandardCharsets.UTF_8)));
                    Signature signature = Signature.getInstance("SHA256WithRSA");
                    signature.initSign(privateKey);
                    String s = Base64.getEncoder()
                            .encodeToString(cipher
                                    .doFinal(str.getBytes(StandardCharsets.UTF_8)));
                    byte[] data = s.getBytes(StandardCharsets.UTF_8);
                    signature.update(data);
                    byte[] digitalSignature = signature.sign();
                    msg += "digital"+ Arrays.toString(digitalSignature);
                    String st = Base64.getEncoder()
                            .encodeToString(cipher
                                    .doFinal(str.getBytes(StandardCharsets.UTF_8)));
                    System.out.println("Сообщение для отправки:"+ str +"\n");
                    System.out.println("Отправленное зашифрованное сообщение: "+st+"\n");
                } catch (NoSuchAlgorithmException
                        | NoSuchPaddingException
                        | InvalidKeySpecException | InvalidKeyException
                        | BadPaddingException | IllegalBlockSizeException | SignatureException ex) {
                    ex.printStackTrace();
                }
                connect(message);
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
    }
    public static void main(String[] args) throws IOException {
        Client client = new Client();
    }

    public void connect(String btn) throws IOException {
        System.out.println("клиент запущен");
        Socket socket = new Socket("127.0.0.1",port);
        BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter pw = new PrintWriter(socket.getOutputStream(),true);
        pw.println(msg);//отправка на сервер сообщения
        while ((msg = br.readLine()) != null){
            if(msg.equals("Disconnect")){
                System.out.println("отключение от сервера");
                break;
            }
            System.out.println(msg);//получение сообщения от сервера
            if(btn.equals(keyGeneration)) {
                int pos = msg.indexOf("!") + 1;
                String sub_str = msg.substring(0, pos);
                System.out.println(sub_str + "\n");
                byteKey = getByteKey(msg, "а");
                pw.println("Disconnect");
            }
            if(btn.equals(message)){
                pw.println("Disconnect");
            }
        }
        br.close();
        pw.close();
        socket.close();
    }
    public byte[] getByteKey(String str,String separator){
        int pos = str.indexOf(separator)+1;
        String sub_str = str.substring(pos);
        sub_str = sub_str.substring(1,sub_str.length()-1);
        sub_str = sub_str.replaceAll("\\s","");
        String[] stringsByte = sub_str.split(",");
        byte[] keyBytes = new byte[stringsByte.length];
        for(int i = 0; i < keyBytes.length; i++){
            keyBytes[i] = Byte.parseByte(stringsByte[i]);
        }
        return keyBytes;
    }

}
