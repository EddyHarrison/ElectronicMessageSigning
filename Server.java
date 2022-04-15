import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

public class Server {
    final int port = 1777;
    static final String keyGeneration = "KEY_GENERATION";
    static final String message = "MESSAGE";
    static JTextArea textArea;
    static String msg;
    static GenerationKey generationKey ;
    static String verify;


    public Server(){
    }

    public static void main(String[] args) throws InvalidKeyException,
            BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {

        connect(1777);
    }

    public static void connect( int port) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        Server server = new Server();
        try{
            ServerSocket serverSocket = new ServerSocket(port);
            while (true){
                System.out.println("ожидание подключения... "+"\n");
                try(Socket localSocket = serverSocket.accept();
                    PrintWriter pw = new PrintWriter(localSocket.getOutputStream(),true);
                    BufferedReader br = new BufferedReader(new InputStreamReader(localSocket.getInputStream())))
                {
                    String str;
                    while ((str = br.readLine()) != null){
                        if(str.length() > 20){
                            int index = str.lastIndexOf("digital");
                            verify = str.substring(index+"digital".length());
                            System.out.println(verify);
                            msg = str.substring(message.length(),index);
                            str = str.substring(0,message.length());
                        }
                        //то что нам пришло от клиента выводим в консоль
                        System.out.println("Команда: " + str+"\n");
                        if(str.equals("Disconnect")){
                            pw.println("Disconnect");
                            break;
                        }else {
                            //то что сервер возвращает клиенту
                            if(str.equals(keyGeneration)){
                                generationKey = new GenerationKey(1024);
                                str = "Сообщение от сервера"+ Arrays
                                        .toString(generationKey.getPrivateKey().getEncoded());
                                System.out.println("ключ создан успешно !"+"\n");
                                pw.println(str);

                            }else if(str.equals(message)){
                                System.out.println("зашифрованное: "+msg+"\n");
                                System.out.println("Подлинность ЭП: "+verifySting(verify));
                                System.out.println("расшифрованное сообщение: "+ server.decryptMSG(msg));
                                pw.println(str);
                            }
                        }
                    }
                } catch (IOException ex){
                    ex.printStackTrace(System.out);
                } catch (NoSuchAlgorithmException | SignatureException e) {
                    e.printStackTrace();
                }
            }
        }catch (IOException ex){
            ex.printStackTrace(System.out);
        }
    }

    public String decryptMSG(String encryptedMSG) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,generationKey.getPublicKey());
        return new String(cipher.doFinal(Base64.getDecoder().
                decode(encryptedMSG)),StandardCharsets.UTF_8);
    }

    public static boolean verifySting(String str) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String sub_str = str.substring(1,str.length()-1);
        sub_str = sub_str.replaceAll("\\s","");
        String[] arr = sub_str.split(",");
        byte[] data = new byte[arr.length];
        for(int i = 0; i < arr.length; i++){
            data[i] = Byte.parseByte(arr[i]);
        }
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(generationKey.getPublicKey());
        byte[] data1 = msg.getBytes(StandardCharsets.UTF_8);
        signature.update(data1);
        return signature.verify(data);
    }
}
