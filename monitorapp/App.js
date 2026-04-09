import { createAppContainer } from "react-navigation";
import { createStackNavigator } from "react-navigation-stack";
import HomeScreen from "./screens/HomeScreen";
import MainScreen from "./screens/MainScreen";
import AttacksScreen from "./screens/AttacksScreen";
import DefenseScreen from "./screens/DefenseScreen";
import AlertsScreen from "./screens/AlertsScreen";

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
  },
  {
    initialRouteName: "Home",
  }
);

export default createAppContainer(navigator);