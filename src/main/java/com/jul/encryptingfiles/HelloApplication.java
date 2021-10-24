package com.jul.encryptingfiles;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.IOException;

public class HelloApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("design.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 600, 400);
        stage.setTitle("Encrypt-Decrypt");
        stage.setScene(scene);
        stage.setResizable(false);
        stage.getIcons().add(new Image("https://i.imgur.com/AElrwFI.png"));
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}