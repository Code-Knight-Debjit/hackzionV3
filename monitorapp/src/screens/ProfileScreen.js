import React from "react";
import { View, Text, StyleSheet, TouchableOpacity } from "react-native";

const ProfileScreen = ({ navigation }) => {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Profile</Text>
      <Text style={styles.description}>This is your profile screen.</Text>
      <TouchableOpacity style={styles.button} onPress={() => navigation.goBack()}>
        <Text style={styles.buttonText}>Back</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#10141a",
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
  },
  title: {
    color: "#FFFFFF",
    fontSize: 28,
    fontWeight: "700",
    marginBottom: 12,
  },
  description: {
    color: "#A0A6B5",
    fontSize: 16,
    textAlign: "center",
    marginBottom: 24,
  },
  button: {
    backgroundColor: "#00BFFF",
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 14,
  },
  buttonText: {
    color: "#10141a",
    fontWeight: "700",
    fontSize: 16,
  },
});

export default ProfileScreen;
