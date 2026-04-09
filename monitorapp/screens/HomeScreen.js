import React, { useState } from "react";
import { Text, StyleSheet, View, TextInput, TouchableOpacity, Alert } from "react-native";

const HomeScreen = ({ navigation }) => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    // Predefined credentials
    const VALID_USERNAME = "admin";
    const VALID_PASSWORD = "pass";

    const handleLogin = () => {
        if (username === "" || password === "") {
            Alert.alert("Error", "Please enter both username and password");
            return;
        }

        if (username === VALID_USERNAME && password === VALID_PASSWORD) {
            setUsername("");
            setPassword("");
            navigation.navigate("Main");
        } else {
            Alert.alert("Error", "Invalid username or password");
            setPassword("");
        }
    };

    return (
        <View style={styles.background}>
            <View style={styles.container}>
                <Text style={styles.header}>CyberPulse</Text>
                <Text style={styles.subheading}>Cybersecurity Log Monitor</Text>

                <View style={styles.formContainer}>
                    <Text style={styles.label}>Username</Text>
                    <TextInput
                        style={styles.input}
                        placeholder="Enter username"
                        placeholderTextColor="#999"
                        value={username}
                        onChangeText={setUsername}
                        autoCorrect={false}
                        autoCapitalize="none"
                    />

                    <Text style={styles.label}>Password</Text>
                    <TextInput
                        style={styles.input}
                        placeholder="Enter password"
                        placeholderTextColor="#999"
                        secureTextEntry={true}
                        value={password}
                        onChangeText={setPassword}
                    />

                    <TouchableOpacity style={styles.loginButton} onPress={handleLogin}>
                        <Text style={styles.loginButtonText}>Login</Text>
                    </TouchableOpacity>
                </View>
            </View>
        </View>
    );
};

const styles = StyleSheet.create({
    background: {
        backgroundColor: "#10141a",
        width: "100%",
        height: "100%",
    },
    container: {
        flex: 1,
        justifyContent: "center",
        alignItems: "center",
        padding: 20,
    },
    header: {
        color: "#FFFFFF",
        fontSize: 50,
        fontWeight: "bold",
        textAlign: "center",
        marginBottom: 10,
    },
    subheading: {
        color: "#00BFFF",
        fontSize: 18,
        textAlign: "center",
        marginBottom: 40,
    },
    formContainer: {
        width: "100%",
        maxWidth: 400,
        backgroundColor: "#1a1f26",
        padding: 30,
        borderRadius: 10,
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.3,
        shadowRadius: 3,
        elevation: 5,
    },
    label: {
        color: "#FFFFFF",
        fontSize: 16,
        fontWeight: "600",
        marginBottom: 8,
    },
    input: {
        backgroundColor: "#2a3038",
        color: "#FFFFFF",
        borderColor: "#00BFFF",
        borderWidth: 1,
        padding: 15,
        marginBottom: 20,
        borderRadius: 5,
        fontSize: 16,
    },
    loginButton: {
        backgroundColor: "#00BFFF",
        padding: 15,
        borderRadius: 5,
        alignItems: "center",
        marginTop: 10,
    },
    loginButtonText: {
        color: "#FFFFFF",
        fontSize: 18,
        fontWeight: "bold",
    },
    credentialsText: {
        color: "#00BFFF",
        fontSize: 14,
        fontWeight: "bold",
        marginTop: 20,
        marginBottom: 8,
    },
    credentialsInfo: {
        color: "#999",
        fontSize: 12,
        marginBottom: 4,
    },
});

export default HomeScreen;