import { createAppContainer } from "react-navigation";
import { createStackNavigator } from "react-navigation-stack";
import HomeScreen from "./src/screens/HomeScreen";
import MainScreen from "./src/screens/MainScreen";
import AttacksScreen from "./src/screens/AttacksScreen";
import DefenseScreen from "./src/screens/DefenseScreen";
import AlertsScreen from "./src/screens/AlertsScreen";
import ProfileScreen from "./src/screens/ProfileScreen";

const navigator = createStackNavigator(
  {
    Home: {
      screen: HomeScreen,
      navigationOptions: {
        headerShown: false,
      },
    },
    Main: {
      screen: MainScreen,
      navigationOptions: {
        headerShown: false,
      },
    },
    Attacks: {
      screen: AttacksScreen,
      navigationOptions: {
        headerShown: false,
      },
    },
    Defense: {
      screen: DefenseScreen,
      navigationOptions: {
        headerShown: false,
      },
    },
    Alerts: {
      screen: AlertsScreen,
      navigationOptions: {
        headerShown: false,
      },
    },
    Profile: {
      screen: ProfileScreen,
      navigationOptions: {
        headerShown: false,
      },
    },
  },
  {
    initialRouteName: "Home",
  }
);

export default createAppContainer(navigator);