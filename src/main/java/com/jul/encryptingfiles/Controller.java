package com.jul.encryptingfiles;

import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
public class Controller {
    //fx:controller="com.jul.encryptingfiles.Controller"
    public Button ChooseFileButton;
    public Button EncryptButton;
    public Button DecryptButton;
    public TextField NameOfFile;
    File file;
    BufferedWriter writer;
    SecretKey key;
    IvParameterSpec iv;
    Boolean isEncrypted = false;

    public void chooseFile() {
        try{
            FileChooser fileChooser = new FileChooser();
            file = fileChooser.showOpenDialog(ChooseFileButton.getScene().getWindow());
            if(file!=null && file.length()>0){
                HelpfulMethods.readFile(file);
                writer = new BufferedWriter(new FileWriter(file.getPath(), true));
                NameOfFile.setText(file.getName());
                writer.flush();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }


    }

    public void encryptFile() throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        if(file!=null) {
            try {
                if (!isEncrypted) {
                    //128 192 256
                    key = HelpfulMethods.generateKey(256);
                    iv = HelpfulMethods.generateIv();
                    HelpfulMethods.data = HelpfulMethods.encrypt("AES/CBC/PKCS5PADDING", HelpfulMethods.data, key, iv);
                    isEncrypted = true;
                    writer = new BufferedWriter(new FileWriter(file.getPath(), false));
                    writer.write(HelpfulMethods.data);
                    writer.flush();
                    System.out.println("the encrypted text is " + HelpfulMethods.data);
                }
            } catch (NoSuchAlgorithmException e) {
                System.out.println("The algorithm you've chosen doesn't exist!");
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                System.out.println("Invalid argument parameter!");
                e.printStackTrace();
            } catch (IOException e) {
                System.out.println("An error occurred!");
                throw new RuntimeException(e);
            }
        } else{
            System.out.println("No text to encrypt!");
        }
    }

    public void decryptFile() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        if(isEncrypted){
            HelpfulMethods.data = HelpfulMethods.decrypt("AES/CBC/PKCS5PADDING", HelpfulMethods.data, key, iv);
            isEncrypted = false;
            writer = new BufferedWriter(new FileWriter(file.getPath(), false));
            writer.write(HelpfulMethods.data);
            writer.flush();
            System.out.println("the decrypted text is " + HelpfulMethods.data);
        } else {
            System.out.println("Text is not encrypted yet!");
        }

    }
}
