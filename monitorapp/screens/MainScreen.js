import React, { useEffect } from "react";
import { Text, StyleSheet, View, TouchableOpacity, Alert } from "react-native";
import Feather from '@expo/vector-icons/Feather';

const MainScreen = ({ navigation }) => {
    const highVulnAttacks = [
        { name: "SQL Injection", severity: "Critical", timestamp: "10:30" },
        { name: "XSS Attack", severity: "Critical", timestamp: "10:45" },
        { name: "Buffer Overflow", severity: "Critical", timestamp: "11:00" },
    ];

    useEffect(() => {
        if (highVulnAttacks.length > 0) {
            Alert.alert(
                "High Vulnerability Attack Detected",
                `${highVulnAttacks.length} critical attacks detected!`,
                [{ text: "Acknowledged" }]
            );
        }
    }, []);

    return (
        <View style={styles.container}>
            <View style={styles.header}>
                <TouchableOpacity
                    onPress={() => navigation.navigate('Home')}
                >
                    <Feather name="log-out" size={24} color="black" />
                </TouchableOpacity>
            </View>
            <View style={styles.content}>
                <Text style={styles.contentTitle}>Dashboard</Text>
                <Text style={styles.welcomeText}>Welcome to CyberPulse Security Monitor</Text>

                {highVulnAttacks.length > 0 && (
                    <View style={styles.alertSection}>
                        <Text style={styles.alertTitle}>⚠️ High Vulnerability Attacks Detected</Text>
                        <Text style={styles.alertCount}>{highVulnAttacks.length} critical attacks found</Text>
                        <TouchableOpacity
                            style={styles.alertButton}
                            onPress={() => navigation.navigate('Alerts')}
                        >
                            <Text style={styles.alertButtonText}>Click here to view them</Text>
                        </TouchableOpacity>
                    </View>
                )}
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
    header: {
        flexDirection: "row",
        justifyContent: "flex-end",
        padding: 20,
        paddingTop: 40,
    },
    logoutButton: {
        backgroundColor: "#FF6B6B",
        paddingHorizontal: 20,
        paddingVertical: 10,
        borderRadius: 5,
    },
    logoutIcon: {
        fontSize: 24,
        color: "white",
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
        marginTop: -100,
    },
    welcomeText: {
        fontSize: 16,
        color: "#666",
        textAlign: "center",
        marginBottom: 30,
    },
    alertSection: {
        backgroundColor: "#FF6B6B",
        padding: 20,
        borderRadius: 10,
        width: "100%",
        maxWidth: 350,
        alignItems: "center",
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.3,
        shadowRadius: 3,
        elevation: 5,
    },
    alertTitle: {
        fontSize: 18,
        color: "white",
        fontWeight: "bold",
        marginBottom: 8,
    },
    alertCount: {
        fontSize: 14,
        color: "white",
        marginBottom: 15,
        opacity: 0.9,
    },
    alertButton: {
        backgroundColor: "white",
        paddingHorizontal: 20,
        paddingVertical: 10,
        borderRadius: 5,
    },
    alertButtonText: {
        color: "#FF6B6B",
        fontSize: 16,
        fontWeight: "bold",
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