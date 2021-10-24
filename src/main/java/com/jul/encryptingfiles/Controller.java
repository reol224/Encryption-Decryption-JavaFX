package com.jul.encryptingfiles;

import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
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
    SecretKey key;
    IvParameterSpec iv;
    Boolean isEncrypted = false;
    String encryptedText;
    String decryptedText;

    public void chooseFile() {
        FileChooser fileChooser = new FileChooser();
        file = fileChooser.showOpenDialog(ChooseFileButton.getScene().getWindow());
        if(file!=null){
            HelpfulMethods.readFile(file);
            NameOfFile.setText(file.getName());
        }
        else{
            System.out.println("You didn't choose any file!");
        }

    }

    public void encryptFile() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        if(file!=null) {
            try {
                if (!isEncrypted) {
                    //128 192 256
                    key = HelpfulMethods.generateKey(256);
                    iv = HelpfulMethods.generateIv();
                    encryptedText = HelpfulMethods.encrypt("AES/CBC/PKCS5PADDING", HelpfulMethods.data, key, iv);
                    isEncrypted = true;
                    System.out.println("the encrypted text is " + encryptedText);
                }
            } catch (NoSuchAlgorithmException e) {
                System.out.println("The algorithm you've chosen doesn't exist!");
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                System.out.println("Invalid argument parameter!");
                e.printStackTrace();
            }
        } else{
            System.out.println("No text to encrypt!");
        }
    }

    public void decryptFile() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if(isEncrypted){
            decryptedText = HelpfulMethods.decrypt("AES/CBC/PKCS5PADDING", encryptedText, key, iv);
            isEncrypted = false;
            System.out.println("the decrypted text is " + decryptedText);
        } else {
            System.out.println("Text is not encrypted yet!");
        }

    }
}
