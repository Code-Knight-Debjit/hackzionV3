import React from "react";
import { Text, StyleSheet, View, TouchableOpacity } from "react-native";

const MainScreen = ({ navigation }) => {
    return (
        <View style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.contentTitle}>Dashboard</Text>
                <Text style={styles.welcomeText}>Welcome to CyberPulse Security Monitor</Text>
            </View>

            <View style={styles.bottomNav}>
                <TouchableOpacity
                    style={[styles.navButton, styles.navButtonActive]}
                >
                    <Text style={[styles.navText, styles.navTextActive]}>HOME</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Attacks')}
                >
                    <Text style={styles.navText}>ATTACKS</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Defense')}
                >
                    <Text style={styles.navText}>DEFENSE</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Alerts')}
                >
                    <Text style={styles.navText}>ALERTS</Text>
                </TouchableOpacity>
            </View>
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: "#FAF9F6",
    },
    content: {
        flex: 1,
        justifyContent: "center",
        alignItems: "center",
        padding: 20,
    },
    contentTitle: {
        fontSize: 28,
        fontWeight: "bold",
        color: "#FF6B6B",
        marginBottom: 15,
    },
    welcomeText: {
        fontSize: 16,
        color: "#666",
        textAlign: "center",
    },
    bottomNav: {
        flexDirection: "row",
        backgroundColor: "#2a3038",
        borderTopWidth: 1,
        borderTopColor: "#FF6B6B",
        height: 60,
    },
    navButton: {
        flex: 1,
        justifyContent: "center",
        alignItems: "center",
    },
    navButtonActive: {
        borderBottomWidth: 3,
        borderBottomColor: "#00BFFF",
    },
    navText: {
        color: "#999",
        fontSize: 12,
        fontWeight: "600",
    },
    navTextActive: {
        color: "#00BFFF",
    },
});

export default MainScreen;