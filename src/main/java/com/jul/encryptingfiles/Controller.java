package com.jul.encryptingfiles;

import javafx.fxml.FXML;
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
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import static com.jul.encryptingfiles.EncodeDecode.*;

public class Controller {
    @FXML
    public Button ChooseFileButton;
    public Button EncryptButton;
    public Button DecryptButton;
    public TextField NameOfFile;

    private File file;
    private BufferedWriter writer;
    private SecretKey key;
    private IvParameterSpec iv;
    private boolean isEncrypted = false;

    private static final Logger log = Logger.getLogger(Controller.class.getName());

    public void chooseFile() {
        log.info("Choose file button clicked");
        try {
            FileChooser fileChooser = new FileChooser();
            file = fileChooser.showOpenDialog(ChooseFileButton.getScene().getWindow());
            if (file != null && file.length() > 0) {
                readFile(file);
                writer = new BufferedWriter(new FileWriter(file.getPath(), true));
                NameOfFile.setText(file.getName());
                writer.flush();
            }
        } catch (Exception ex) {
            log.info("Error: " + ex.getMessage());
        }
    }

    public void encryptFile() {
        if (file != null) {
            try {
                if (!isEncrypted) {
                    key = generateKey(256);
                    iv = generateIv();

                    if (data != null) {
                        String encryptedData = encrypt("AES/CBC/PKCS5PADDING", data, key, iv);
                        isEncrypted = true;
                        writer = new BufferedWriter(new FileWriter(file.getPath(), false));
                        writer.write(encryptedData);
                        writer.flush();
                        log.info("The encrypted text is: " + encryptedData);
                    } else {
                        log.warning("Encryption failed. Input data is null.");
                    }
                }
            } catch (NoSuchAlgorithmException e) {
                log.warning("The algorithm you've chosen doesn't exist!");
                log.info("Error: " + e.getMessage());
            } catch (InvalidAlgorithmParameterException e) {
                log.warning("Invalid argument parameter!");
                log.info("Error: " + e.getMessage());
            } catch (IOException e) {
                log.warning("An error occurred!");
                log.info("Error: " + e.getMessage());
            } catch (NoSuchPaddingException | InvalidKeyException |
                     BadPaddingException | IllegalBlockSizeException e) {
                log.warning("Encryption error occurred!");
                log.info("Error: " + e.getMessage());
            }
        } else {
            log.warning("No file selected!");
        }
    }

    public void decryptFile() {
        if (isEncrypted) {
            try {
                byte[] encryptedData = Files.readAllBytes(file.toPath());
                String decryptedData = decrypt("AES/CBC/PKCS5PADDING", new String(encryptedData), key, iv);

                if (decryptedData != null) {
                    isEncrypted = false;
                    writer = new BufferedWriter(new FileWriter(file.getPath(), false));
                    writer.write(decryptedData);
                    writer.flush();
                    log.info("The decrypted text is: " + decryptedData);
                } else {
                    log.warning("Decryption failed. Decrypted data is null.");
                }
            } catch (InvalidAlgorithmParameterException | NoSuchPaddingException |
                     IllegalBlockSizeException | NoSuchAlgorithmException |
                     BadPaddingException | InvalidKeyException | IOException e) {
                log.warning("Decryption error occurred!");
                log.info("Error: " + e.getMessage());
            }
        } else {
            log.info("Text is not encrypted yet!");

        }
    }
}