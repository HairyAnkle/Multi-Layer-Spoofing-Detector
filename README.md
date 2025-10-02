# AI-Based Multi-Layer Spoofing Detection

This project is a WPF application designed to detect and prevent spoofing attacks using AI-based multi-layer analysis. It provides packet capture and analysis capabilities.

# [Here](https://github.com/HairyAnkle/Multi-Layer-Spoofing-Detector/tree/master)

## Prerequisites

Before setting up the project, ensure you have the following installed:

1. **.NET 8 SDK**  
   Download and install the latest .NET 8 SDK from the [official .NET website](https://dotnet.microsoft.com/).

2. **Visual Studio 2022**  
   - Install Visual Studio 2022 with the following workloads:
     - **.NET Desktop Development**
     - **WPF Development**

3. **Git**  
   Ensure Git is installed to clone the repository. You can download it from [Git's official website](https://git-scm.com/).

4. **NuGet Packages**  
   The project uses NuGet for dependency management. Visual Studio will automatically restore these packages.   

## Setup Instructions

Follow these steps to set up and run the project:

1. **Clone the Repository**  
   Open a terminal and run the following command:
   ```
   git clone https://github.com/HairyAnkle/Multi-Layer-Spoofing-Detector.git
   ```
   
   Navigate to the project directory:

   ```
   cd Multi-Layer-Spoofing-Detector
   ```
   
3. **Open the Project in Visual Studio**  
- Launch Visual Studio 2022.
- Open the solution file (`Multi-Layer-Spoofing-Detector.sln`) located in the project directory.

3. **Restore NuGet Packages**  
- Visual Studio should automatically restore the required NuGet packages when the solution is loaded.
- If not, restore them manually by navigating to __Tools > NuGet Package Manager > Manage NuGet Packages for Solution__ and clicking "Restore."

4. **Build the Solution**  
- Set the build configuration to `Debug` or `Release`.
- Build the solution by pressing `Ctrl+Shift+B` or navigating to __Build > Build Solution__.

5. **Run the Application**  
- Press `F5` to start the application in debug mode.
- Alternatively, navigate to __Debug > Start Without Debugging__ to run the application.

## Features

- **Network Monitoring**: Displays network status and detects spoofing threats.
- **Packet Capture and Analysis**: Capture network packets and analyze them for ARP, DNS, and IP spoofing.
- **Customizable Settings**: Adjust thresholds, enable notifications, and configure report preferences.
- **Reports**: Export analysis results in CSV or JSON formats.

## Project Structure
- **MainWindow.xaml**: Defines the UI layout and styles for the application.
- **MainWindow.xaml.cs**: Contains the logic for handling user interactions and application behavior.
- **App.xaml**: Configures application-wide resources and settings.

## Troubleshooting

- **NuGet Restore Issues**: If NuGet packages fail to restore, try running the following command in the terminal:
  ```
  dotnet restore
  ```
- **Build Errors**: Ensure you have the correct version of the .NET SDK and Visual Studio installed.

## Contributing

Contributions are welcome! Feel free to fork the repository and submit pull requests.

## License

This project is licensed under the [MIT License](LICENSE).

---

Enjoy using the AI-Based Multi-Layer Spoofing Detection and Prevention System!

   
